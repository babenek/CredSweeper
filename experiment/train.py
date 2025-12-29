import hashlib
import os
import pathlib
import pickle
import random
import subprocess
import sys
from datetime import datetime
from typing import Dict, Any, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.utils import compute_class_weight
from sklearn.metrics import accuracy_score, precision_score, recall_score

from data_loader import read_detected_data, read_metadata, join_label, get_y_labels
from pytorch_evaluate_model import evaluate_model
from features import prepare_data
from hyperparameters import HP_DICT
from pytorch_log_callback import LogCallback
from model_config_preprocess import model_config_preprocess, ML_CONFIG_PATH
from pytorch_plot import save_plot
from prepare_data import prepare_train_data, RESULTS_DIR
from pytorch_model import PyTorchMlModel, create_pytorch_model, get_model_summary
from optuna_optimizer import OptunaOptimizer, get_default_hyperparams


class PyTorchTrainer:
    """PyTorch-based trainer for the ML model"""
    
    def __init__(self, device: torch.device = None):
        self.device = device if device else torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        print(f"Using device: {self.device}")
        
    def train_epoch(self, 
                   model: PyTorchMlModel,
                   train_loader: DataLoader,
                   optimizer: optim.Optimizer,
                   criterion: nn.Module,
                   class_weights: Dict[int, float] = None) -> Tuple[float, Dict[str, float]]:
        """Train model for one epoch"""
        model.train()
        total_loss = 0.0
        all_predictions = []
        all_targets = []
        
        # Setup class weights for loss function
        if class_weights:
            pos_weight = torch.tensor([class_weights[1] / class_weights[0]]).to(self.device)
            criterion = nn.BCELoss(weight=pos_weight)
        
        for batch_idx, (line_data, variable_data, value_data, feature_data, targets) in enumerate(train_loader):
            line_data = line_data.to(self.device)
            variable_data = variable_data.to(self.device)
            value_data = value_data.to(self.device)
            feature_data = feature_data.to(self.device)
            targets = targets.to(self.device).float()
            
            optimizer.zero_grad()
            outputs = model(line_data, variable_data, value_data, feature_data)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
            # Calculate metrics
            predictions = (outputs > 0.5).float()
            all_predictions.extend(predictions.cpu().numpy())
            all_targets.extend(targets.cpu().numpy())
        
        avg_loss = total_loss / len(train_loader)
        accuracy = accuracy_score(all_targets, all_predictions)
        precision = precision_score(all_targets, all_predictions, zero_division=0)
        recall = recall_score(all_targets, all_predictions, zero_division=0)
        
        metrics = {
            'loss': avg_loss,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall
        }
        
        return avg_loss, metrics
    
    def validate_epoch(self,
                      model: PyTorchMlModel,
                      val_loader: DataLoader,
                      criterion: nn.Module) -> Tuple[float, Dict[str, float]]:
        """Validate model for one epoch"""
        model.eval()
        total_loss = 0.0
        all_predictions = []
        all_targets = []
        
        with torch.no_grad():
            for line_data, variable_data, value_data, feature_data, targets in val_loader:
                line_data = line_data.to(self.device)
                variable_data = variable_data.to(self.device)
                value_data = value_data.to(self.device)
                feature_data = feature_data.to(self.device)
                targets = targets.to(self.device).float()
                
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
        
        metrics = {
            'loss': avg_loss,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall
        }
        
        return avg_loss, metrics
    
    def train(self,
             model: PyTorchMlModel,
             train_loader: DataLoader,
             val_loader: DataLoader,
             epochs: int,
             patience: int,
             class_weights: Dict[int, float] = None) -> Tuple[Dict[str, list], int]:
        """Train the model with early stopping"""
        
        optimizer = optim.Adam(model.parameters(), lr=0.001)
        criterion = nn.BCELoss()
        
        history = {
            'loss': [],
            'val_loss': [],
            'accuracy': [],
            'val_accuracy': [],
            'precision': [],
            'val_precision': [],
            'recall': [],
            'val_recall': []
        }
        
        best_val_loss = float('inf')
        patience_counter = 0
        best_epoch = 0
        
        for epoch in range(epochs):
            # Train
            train_loss, train_metrics = self.train_epoch(model, train_loader, optimizer, criterion, class_weights)
            
            # Validate
            val_loss, val_metrics = self.validate_epoch(model, val_loader, criterion)
            
            # Update history
            history['loss'].append(train_loss)
            history['val_loss'].append(val_loss)
            history['accuracy'].append(train_metrics['accuracy'])
            history['val_accuracy'].append(val_metrics['accuracy'])
            history['precision'].append(train_metrics['precision'])
            history['val_precision'].append(val_metrics['precision'])
            history['recall'].append(train_metrics['recall'])
            history['val_recall'].append(val_metrics['recall'])
            
            # Print progress
            print(f"Epoch {epoch+1}/{epochs} - "
                  f"loss: {train_loss:.4f} - val_loss: {val_loss:.4f} - "
                  f"val_accuracy: {val_metrics['accuracy']:.4f} - "
                  f"val_precision: {val_metrics['precision']:.4f} - "
                  f"val_recall: {val_metrics['recall']:.4f}")
            
            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                best_epoch = epoch
                # Save best model
                torch.save(model.state_dict(), 'best_model_temp.pth')
            else:
                patience_counter += 1
                
            if patience_counter >= patience:
                print(f"Early stopping at epoch {epoch+1}")
                break
        
        # Load best model
        if os.path.exists('best_model_temp.pth'):
            model.load_state_dict(torch.load('best_model_temp.pth'))
            os.remove('best_model_temp.pth')
        
        return history, best_epoch


def create_dataloaders(x_train_line: np.ndarray,
                      x_train_variable: np.ndarray,
                      x_train_value: np.ndarray,
                      x_train_features: np.ndarray,
                      y_train: np.ndarray,
                      x_test_line: np.ndarray,
                      x_test_variable: np.ndarray,
                      x_test_value: np.ndarray,
                      x_test_features: np.ndarray,
                      y_test: np.ndarray,
                      batch_size: int) -> Tuple[DataLoader, DataLoader]:
    """Create PyTorch dataloaders"""
    
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
    
    return train_loader, val_loader


def train_pytorch(
    cred_data_location: str,
    jobs: int,
    epochs: int,
    batch_size: int,
    patience: int,
    doc_target: bool,
    use_tuner: bool,
    eval_test: bool,
    eval_train: bool,
    eval_full: bool,
) -> str:
    """Main training function using PyTorch+Optuna"""
    
    # Set random seeds
    torch.manual_seed(random.randint(1, 0xffffffff))
    np.random.seed(random.randint(1, 0xffffffff))
    
    print(f"Memory at start: {LogCallback.get_memory_info()}", flush=True)
    
    subprocess.check_call(f"md5sum {ML_CONFIG_PATH.absolute()}", shell=True)
    
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    print(f"Train model on data from {cred_data_location}", flush=True)
    meta_checksum, data_checksum = prepare_train_data(cred_data_location, jobs, doc_target)
    
    df_all_file = RESULTS_DIR / f"{meta_checksum}-{data_checksum}.pkl"
    if df_all_file.exists():
        df_all = pd.read_pickle(df_all_file)
        print(f"Read from {df_all_file}", flush=True)
    else:
        detected_data = read_detected_data(RESULTS_DIR / f"detected_data.{data_checksum}.json")
        print(f"CredSweeper detected {len(detected_data)} credentials without ML", flush=True)
        meta_data = read_metadata(f"{cred_data_location}/meta")
        print(f"Metadata markup: {len(meta_data)} items", flush=True)
        df_all = join_label(detected_data, meta_data, cred_data_location)
        df_all.to_pickle(df_all_file)
        print(f"Stored to {df_all_file}", flush=True)
        del detected_data
        del meta_data
    
    # Handle ML config updates
    trial_cnt = 3
    while 0 < trial_cnt:
        trial_cnt -= 1
        try:
            thresholds = model_config_preprocess(df_all, doc_target)
            break
        except RuntimeError as exc:
            if "RESTART:" in str(exc) and 0 <= trial_cnt:
                print(str(exc), flush=True)
                continue
            else:
                raise exc
    else:
        raise RuntimeError("Something went wrong")
    
    # Split data
    df_train, df_test = train_test_split(df_all, test_size=0.15, random_state=random.randint(1, 1 << 32))
    len_df_train = len(df_train)
    print(f"Train size: {len_df_train}", flush=True)
    len_df_test = len(df_test)
    print(f"Test size: {len_df_test}", flush=True)
    
    # Prepare data
    print(f"Prepare full data", flush=True)
    x_full_line, x_full_variable, x_full_value, x_full_features = prepare_data(df_all)
    y_full = get_y_labels(df_all)
    del df_all
    
    print(f"Prepare train data", flush=True)
    x_train_line, x_train_variable, x_train_value, x_train_features = prepare_data(df_train)
    y_train = get_y_labels(df_train)
    del df_train
    
    print(f"Class-1 prop on train: {np.mean(y_train):.4f}", flush=True)
    
    # Calculate class weights
    classes = np.unique(y_train)
    class_weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
    max_weight = max(class_weights)
    class_weights = [weight / max_weight for weight in class_weights]
    print(f"y_train size:{len(y_train)}, 0: {np.count_nonzero(y_train == 0)}, 1: {np.count_nonzero(y_train == 1)}", flush=True)
    class_weight_dict = dict(zip(classes, class_weights))
    print(f"class_weight: {class_weight_dict}", flush=True)
    
    print(f"Prepare test data", flush=True)
    x_test_line, x_test_variable, x_test_value, x_test_features = prepare_data(df_test)
    y_test = get_y_labels(df_test)
    print(f"Class-1 prop on test: {np.mean(y_test):.4f}", flush=True)
    del df_test
    
    print(f"Memory before training: {LogCallback.get_memory_info()}", flush=True)
    
    # Initialize trainer
    trainer = PyTorchTrainer()
    
    # Hyperparameter optimization with Optuna
    if use_tuner:
        print(f"Starting Optuna hyperparameter optimization...", flush=True)
        optimizer = OptunaOptimizer(
            x_full_line.shape,
            x_full_variable.shape,
            x_full_value.shape,
            x_full_features.shape,
            n_trials=30
        )
        
        optimization_results = optimizer.optimize(
            x_train_line, x_train_variable, x_train_value, x_train_features, y_train,
            x_test_line, x_test_variable, x_test_value, x_test_features, y_test,
            epochs=epochs, patience=patience, batch_size=batch_size
        )
        
        param_kwargs = optimization_results['best_hyperparams']
        print(f"Best hyperparameters: {param_kwargs}", flush=True)
    else:
        print(f"Using default hyperparameters: {HP_DICT}", flush=True)
        param_kwargs = get_default_hyperparams()
    
    # Create final model
    model = create_pytorch_model(
        x_full_line.shape,
        x_full_variable.shape,
        x_full_value.shape,
        x_full_features.shape,
        **param_kwargs
    )
    model.to(trainer.device)
    
    print(get_model_summary(model, x_full_line.shape, x_full_variable.shape, x_full_value.shape, x_full_features.shape))
    
    if not eval_full:
        del x_full_line, x_full_variable, x_full_value, x_full_features, y_full
    
    # Create dataloaders
    train_loader, val_loader = create_dataloaders(
        x_train_line, x_train_variable, x_train_value, x_train_features, y_train,
        x_test_line, x_test_variable, x_test_value, x_test_features, y_test,
        batch_size
    )
    
    print(f"Memory before train: {LogCallback.get_memory_info()}", flush=True)
    
    # Train model
    history, best_epoch = trainer.train(
        model, train_loader, val_loader, epochs, patience, class_weight_dict
    )
    
    print(f"Memory after train: {LogCallback.get_memory_info()}", flush=True)
    
    # Save history
    with open(RESULTS_DIR / f"{current_time}.history.pickle", "wb") as f:
        pickle.dump(history, f)
    
    # Save model
    model_file_name = RESULTS_DIR / f"ml_model_at-{current_time}"
    torch.save({
        'model_state_dict': model.state_dict(),
        'hyperparams': param_kwargs,
        'input_shapes': {
            'line_shape': x_train_line.shape,
            'variable_shape': x_train_variable.shape,
            'value_shape': x_train_value.shape,
            'feature_shape': x_train_features.shape
        }
    }, model_file_name)
    
    # Evaluate model
    if eval_test:
        print(f"Validate results on the test subset. Size: {len(y_test)} {np.mean(y_test):.4f}", flush=True)
        evaluate_model(thresholds, model, [x_test_line, x_test_variable, x_test_value, x_test_features], y_test)
    
    del x_test_line, x_test_variable, x_test_value, x_test_features, y_test
    
    if eval_train:
        print(f"Validate results on the train subset. Size: {len(y_train)} {np.mean(y_train):.4f}", flush=True)
        evaluate_model(thresholds, model, [x_train_line, x_train_variable, x_train_value, x_train_features], y_train)
    
    del x_train_line, x_train_variable, x_train_value, x_train_features, y_train
    
    if eval_full:
        print(f"Validate results on the full set. Size: {len(y_full)} {np.mean(y_full):.4f}", flush=True)
        evaluate_model(thresholds, model, [x_full_line, x_full_variable, x_full_value, x_full_features], y_full)
        del x_full_line, x_full_variable, x_full_value, x_full_features, y_full
    
    # Convert PyTorch model to ONNX
    onnx_model_file = pathlib.Path(__file__).parent.parent / "credsweeper" / "ml_model" / "ml_model.onnx"
    print(f"Converting PyTorch model to ONNX: {onnx_model_file}", flush=True)
    
    # Get input shapes from the saved model metadata
    loaded_checkpoint = torch.load(model_file_name, map_location='cpu')
    input_shapes = loaded_checkpoint['input_shapes']
    
    # Create dummy inputs for ONNX export
    dummy_line_input = torch.randn(1, input_shapes['line_shape'][1], input_shapes['line_shape'][2])
    dummy_variable_input = torch.randn(1, input_shapes['variable_shape'][1], input_shapes['variable_shape'][2])
    dummy_value_input = torch.randn(1, input_shapes['value_shape'][1], input_shapes['value_shape'][2])
    dummy_feature_input = torch.randn(1, input_shapes['feature_shape'][1])
    
    # Remove any existing ONNX files to ensure clean export
    if onnx_model_file.exists():
        onnx_model_file.unlink()
    onnx_data_file = onnx_model_file.with_suffix('.data')
    if onnx_data_file.exists():
        onnx_data_file.unlink()
    
    # Export to ONNX with single file output - disable dynamic axes to avoid slicing issues
    torch.onnx.export(
        model,
        (dummy_line_input, dummy_variable_input, dummy_value_input, dummy_feature_input),
        str(onnx_model_file),
        export_params=True,
        opset_version=18,  # Use newer opset version for better compatibility
        do_constant_folding=True,
        input_names=['line_input', 'variable_input', 'value_input', 'feature_input'],
        output_names=['output'],
        dynamic_axes=None,  # Disable dynamic axes completely to avoid slicing issues
        # Use external_data=False to ensure everything is in one file
        external_data=False
    )
    
    # Remove any .data file that might be created despite external_data=False
    onnx_data_file = onnx_model_file.with_suffix('.data')
    if onnx_data_file.exists():
        onnx_data_file.unlink()
        print(f"Removed auxiliary file: {onnx_data_file}", flush=True)
    
    # Verify ONNX model
    import onnx
    onnx_model = onnx.load(str(onnx_model_file))
    onnx.checker.check_model(onnx_model)
    print("ONNX model verification passed", flush=True)
    
    # Calculate MD5 of ONNX model
    with open(onnx_model_file, "rb") as f:
        onnx_md5 = hashlib.md5(f.read()).hexdigest()
        print(f"ml_model.onnx:{onnx_md5}", flush=True)
    
    with open(ML_CONFIG_PATH, "rb") as f:
        config_md5 = hashlib.md5(f.read()).hexdigest()
        print(f"ml_config.json:{config_md5}", flush=True)
    
    # Save plot
    save_plot(
        stamp=current_time,
        title=f"batch:{batch_size} train:{len_df_train} test:{len_df_test} weights:{class_weights}",
        history=history,
        dir_path=RESULTS_DIR,
        best_epoch=int(best_epoch),
        info=f"ml_config.json:{config_md5} pytorch_model:{model_file_name} best_epoch:{best_epoch}",
    )
    
    return str(model_file_name.absolute())
