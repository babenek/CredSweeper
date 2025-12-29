import optuna
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from typing import Dict, Any, Tuple, Optional
import pickle
import os
from sklearn.metrics import accuracy_score, precision_score, recall_score

from pytorch_model import PyTorchMlModel, create_pytorch_model, get_model_summary
from hyperparameters import HP_DICT


class OptunaOptimizer:
    """Optuna-based hyperparameter optimizer for PyTorch model"""
    
    def __init__(self, 
                 line_shape: Tuple[int, int, int],
                 variable_shape: Tuple[int, int, int],
                 value_shape: Tuple[int, int, int],
                 feature_shape: Tuple[int, int],
                 study_name: str = "pytorch_ml_tuning",
                 direction: str = "minimize",
                 n_trials: int = 30):
        
        self.line_shape = line_shape
        self.variable_shape = variable_shape
        self.value_shape = value_shape
        self.feature_shape = feature_shape
        
        self.study = optuna.create_study(
            study_name=study_name,
            direction=direction,
            sampler=optuna.samplers.TPESampler(seed=42)
        )
        self.n_trials = n_trials
        
    def suggest_hyperparameters(self, trial: optuna.Trial) -> Dict[str, Any]:
        """Suggest hyperparameters based on the original HP_DICT ranges"""
        hyperparams = {}
        
        for param_name, (param_range, default_value) in HP_DICT.items():
            if isinstance(param_range, tuple) and len(param_range) == 3:
                min_val, max_val, step = param_range
                hyperparams[param_name] = trial.suggest_float(
                    param_name, min_val, max_val, step=step
                )
            else:
                hyperparams[param_name] = default_value
                
        return hyperparams
    
    def create_model(self, trial: optuna.Trial) -> PyTorchMlModel:
        """Create model with suggested hyperparameters"""
        hyperparams = self.suggest_hyperparameters(trial)
        return create_pytorch_model(
            self.line_shape,
            self.variable_shape, 
            self.value_shape,
            self.feature_shape,
            **hyperparams
        )
    
    def train_epoch(self, 
                   model: PyTorchMlModel,
                   train_loader: DataLoader,
                   optimizer: optim.Optimizer,
                   criterion: nn.Module,
                   device: torch.device) -> float:
        """Train model for one epoch"""
        model.train()
        total_loss = 0.0
        
        for batch_idx, (line_data, variable_data, value_data, feature_data, targets) in enumerate(train_loader):
            line_data = line_data.to(device)
            variable_data = variable_data.to(device)
            value_data = value_data.to(device)
            feature_data = feature_data.to(device)
            targets = targets.to(device).float()
            
            optimizer.zero_grad()
            outputs = model(line_data, variable_data, value_data, feature_data)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
        return total_loss / len(train_loader)
    
    def validate_epoch(self,
                      model: PyTorchMlModel,
                      val_loader: DataLoader,
                      criterion: nn.Module,
                      device: torch.device) -> Tuple[float, float, float, float]:
        """Validate model for one epoch"""
        model.eval()
        total_loss = 0.0
        all_predictions = []
        all_targets = []
        
        with torch.no_grad():
            for line_data, variable_data, value_data, feature_data, targets in val_loader:
                line_data = line_data.to(device)
                variable_data = variable_data.to(device)
                value_data = value_data.to(device)
                feature_data = feature_data.to(device)
                targets = targets.to(device).float()
                
                outputs = model(line_data, variable_data, value_data, feature_data)
                loss = criterion(outputs, targets)
                total_loss += loss.item()
                
                predictions = (outputs > 0.5).float()
                all_predictions.extend(predictions.cpu().numpy())
                all_targets.extend(targets.cpu().numpy())
        
        avg_loss = total_loss / len(val_loader)
        accuracy = accuracy_score(all_targets, all_predictions)
        precision = precision_score(all_targets, all_predictions, zero_division=0)
        recall = recall_score(all_targets, all_predictions, zero_division=0)
        
        return avg_loss, accuracy, precision, recall
    
    def objective(self, 
                 trial: optuna.Trial,
                 train_loader: DataLoader,
                 val_loader: DataLoader,
                 epochs: int,
                 patience: int,
                 device: torch.device) -> float:
        """Objective function for Optuna optimization"""
        
        # Create model
        model = self.create_model(trial)
        model.to(device)
        
        # Print model summary for first trial
        if trial.number == 0:
            print(get_model_summary(model, self.line_shape, self.variable_shape, self.value_shape, self.feature_shape))
        
        # Setup optimizer and criterion
        optimizer = optim.Adam(model.parameters(), lr=0.001)
        criterion = nn.BCELoss()
        
        # Early stopping
        best_val_loss = float('inf')
        patience_counter = 0
        
        for epoch in range(epochs):
            # Train
            train_loss = self.train_epoch(model, train_loader, optimizer, criterion, device)
            
            # Validate
            val_loss, val_accuracy, val_precision, val_recall = self.validate_epoch(
                model, val_loader, criterion, device
            )
            
            # Report to Optuna
            trial.report(val_loss, epoch)
            
            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
            else:
                patience_counter += 1
                
            if patience_counter >= patience:
                break
                
            # Handle pruning
            if trial.should_prune():
                raise optuna.exceptions.TrialPruned()
        
        return best_val_loss
    
    def optimize(self,
                x_train_line: np.ndarray,
                x_train_variable: np.ndarray,
                x_train_value: np.ndarray,
                x_train_features: np.ndarray,
                y_train: np.ndarray,
                x_test_line: np.ndarray,
                x_test_variable: np.ndarray,
                x_test_value: np.ndarray,
                x_test_features: np.ndarray,
                y_test: np.ndarray,
                epochs: int = 100,
                patience: int = 5,
                batch_size: int = 256) -> Dict[str, Any]:
        """Run hyperparameter optimization"""
        
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        print(f"Using device: {device}")
        
        # Create datasets and dataloaders
        train_dataset = TensorDataset(
            torch.FloatTensor(x_train_line),
            torch.FloatTensor(x_train_variable),
            torch.FloatTensor(x_train_value),
            torch.FloatTensor(x_train_features),
            torch.FloatTensor(y_train)
        )
        
        val_dataset = TensorDataset(
            torch.FloatTensor(x_test_line),
            torch.FloatTensor(x_test_variable),
            torch.FloatTensor(x_test_value),
            torch.FloatTensor(x_test_features),
            torch.FloatTensor(y_test)
        )
        
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
        
        def objective_wrapper(trial):
            return self.objective(trial, train_loader, val_loader, epochs, patience, device)
        
        # Run optimization
        print(f"Starting Optuna optimization with {self.n_trials} trials...")
        self.study.optimize(objective_wrapper, n_trials=self.n_trials)
        
        # Get best hyperparameters
        best_trial = self.study.best_trial
        best_hyperparams = best_trial.params
        
        print("Best trial:")
        print(f"  Value (val_loss): {best_trial.value}")
        print("  Params: ")
        for key, value in best_hyperparams.items():
            print(f"    {key}: {value}")
        
        return {
            'best_hyperparams': best_hyperparams,
            'best_value': best_trial.value,
            'best_trial': best_trial,
            'study': self.study
        }


def get_default_hyperparams() -> Dict[str, float]:
    """Get default hyperparameters from HP_DICT"""
    return {param_name: default_value for param_name, (_, default_value) in HP_DICT.items()}
