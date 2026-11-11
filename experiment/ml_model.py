<<<<<<< HEAD:experiment/src/ml_model.py
from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F

from credsweeper.common.constants import ML_HUNK
from credsweeper import MlValidator

dtype = torch.float32


class MlModel(nn.Module):

    def __init__(self, line_shape: tuple, variable_shape: tuple, value_shape: tuple, feature_shape: tuple, hp=None):
        super(MlModel, self).__init__()
        if hp is None:
            hp = {}
        value_lstm_dropout_rate = self.__get_hyperparam("value_lstm_dropout_rate", hp)
        line_lstm_dropout_rate = self.__get_hyperparam("line_lstm_dropout_rate", hp)
        variable_lstm_dropout_rate = self.__get_hyperparam("variable_lstm_dropout_rate", hp)
        dense_a_dropout_rate = self.__get_hyperparam("dense_a_lstm_dropout_rate", hp)
        dense_b_dropout_rate = self.__get_hyperparam("dense_b_lstm_dropout_rate", hp)

        self.d_type = torch.float32

        self.line_lstm = nn.LSTM(input_size=line_shape[2],
                                 hidden_size=line_shape[1],
                                 batch_first=True,
                                 bidirectional=True)
        self.variable_lstm = nn.LSTM(input_size=variable_shape[2],
                                     hidden_size=variable_shape[1],
                                     batch_first=True,
                                     bidirectional=True)
        self.value_lstm = nn.LSTM(input_size=value_shape[2],
                                  hidden_size=value_shape[1],
                                  batch_first=True,
                                  bidirectional=True)

        self.line_dropout = nn.Dropout(line_lstm_dropout_rate)
        self.variable_dropout = nn.Dropout(variable_lstm_dropout_rate)
        self.value_dropout = nn.Dropout(value_lstm_dropout_rate)

        dense_units = 2 * MlValidator.MAX_LEN + 2 * 2 * ML_HUNK + feature_shape[1]

        self.dense_a = nn.Linear(dense_units, dense_units)
        self.dense_b = nn.Linear(dense_units, dense_units)
        self.dense_final = nn.Linear(dense_units, 1)

        self.a_dropout = nn.Dropout(dense_a_dropout_rate)
        self.b_dropout = nn.Dropout(dense_b_dropout_rate)

    @staticmethod
    def __get_hyperparam(param_name: str, hyperparameters=None) -> Any:
        if param := hyperparameters.get(param_name):
            if isinstance(param, float):
                print(f"'{param_name}' is {param}")
                return param
            else:
                raise ValueError(f"Unexpected '{param_name}': {param}")
        else:
            raise ValueError(f"'{param_name}' was not defined during initialization of the model.")

    def forward(self, line_input: torch.Tensor, variable_input: torch.Tensor, value_input: torch.Tensor,
                feature_input: torch.Tensor):
        line_out, _ = self.line_lstm(line_input)
        line_out = self.line_dropout(line_out[:, -1, :])

        variable_out, _ = self.variable_lstm(variable_input)
        variable_out = self.variable_dropout(variable_out[:, -1, :])

        value_out, _ = self.value_lstm(value_input)
        value_out = self.value_dropout(value_out[:, -1, :])

        joined_features = torch.cat((line_out, variable_out, value_out, feature_input), dim=1)

        dense_a = F.relu(self.dense_a(joined_features))
        dense_a = self.a_dropout(dense_a)

        dense_b = F.relu(self.dense_b(dense_a))
        dense_b = self.b_dropout(dense_b)

        output = torch.sigmoid(self.dense_final(dense_b))
        return output


def binary_accuracy(y_pred, y_true):
    y_pred = (y_pred > 0.5).float()
    correct = (y_pred == y_true).float()
    return correct.mean()


def precision(y_pred, y_true):
    y_pred = (y_pred > 0.5).float()
    tp = (y_pred * y_true).sum()
    fp = (y_pred * (1 - y_true)).sum()
    return tp / (tp + fp + 1e-8)


def recall(y_pred, y_true):
    y_pred = (y_pred > 0.5).float()
    tp = (y_pred * y_true).sum()
    fn = ((1 - y_pred) * y_true).sum()
    return tp / (tp + fn + 1e-8)
=======
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Any, Optional, Tuple
import numpy as np

from credsweeper.common.constants import ML_HUNK
from credsweeper.ml_model.ml_validator import MlValidator


class PyTorchMlModel(nn.Module):
    """PyTorch implementation of the ML model with bidirectional LSTM layers"""
    
    def __init__(self, 
                 line_shape: Tuple[int, int, int],
                 variable_shape: Tuple[int, int, int], 
                 value_shape: Tuple[int, int, int],
                 feature_shape: Tuple[int, int],
                 line_lstm_dropout_rate: float = 0.47,
                 line_lstm_recurrent_dropout_rate: float = 0.21,
                 variable_lstm_dropout_rate: float = 0.42,
                 variable_lstm_recurrent_dropout_rate: float = 0.18,
                 value_lstm_dropout_rate: float = 0.47,
                 value_lstm_recurrent_dropout_rate: float = 0.05,
                 dense_a_drop: float = 0.21,
                 dense_b_drop: float = 0.23):
        super().__init__()
        
        self.line_shape = line_shape
        self.variable_shape = variable_shape
        self.value_shape = value_shape
        self.feature_shape = feature_shape
        
        # LSTM layers
        self.line_lstm = nn.LSTM(
            input_size=line_shape[2],
            hidden_size=line_shape[1],
            batch_first=True,
            dropout=line_lstm_dropout_rate,
            bidirectional=True
        )
        
        self.variable_lstm = nn.LSTM(
            input_size=variable_shape[2],
            hidden_size=variable_shape[1],
            batch_first=True,
            dropout=variable_lstm_dropout_rate,
            bidirectional=True
        )
        
        self.value_lstm = nn.LSTM(
            input_size=value_shape[2],
            hidden_size=value_shape[1],
            batch_first=True,
            dropout=value_lstm_dropout_rate,
            bidirectional=True
        )
        
        # Feature attention mechanism
        self.feature_attention = nn.Linear(feature_shape[1], feature_shape[1], bias=False)
        
        # Calculate dense units (same as original)
        dense_units = 2 * MlValidator.MAX_LEN + 2 * 2 * ML_HUNK + feature_shape[1]
        
        # Dense layers
        lstm_output_size = 2 * line_shape[1] + 2 * variable_shape[1] + 2 * value_shape[1] + feature_shape[1]
        
        self.dense_a = nn.Linear(lstm_output_size, dense_units)
        self.dropout_a = nn.Dropout(dense_a_drop)
        
        self.dense_b = nn.Linear(dense_units, dense_units)
        self.dropout_b = nn.Dropout(dense_b_drop)
        
        self.output_layer = nn.Linear(dense_units, 1)
        
    def forward(self, line_input, variable_input, value_input, feature_input):
        # Process line input
        line_output, _ = self.line_lstm(line_input)
        # Use mean pooling instead of last timestep for better ONNX compatibility
        line_output = torch.mean(line_output, dim=1)
        
        # Process variable input
        variable_output, _ = self.variable_lstm(variable_input)
        # Use mean pooling instead of last timestep for better ONNX compatibility
        variable_output = torch.mean(variable_output, dim=1)
        
        # Process value input
        value_output, _ = self.value_lstm(value_input)
        # Use mean pooling instead of last timestep for better ONNX compatibility
        value_output = torch.mean(value_output, dim=1)
        
        # Feature attention
        feature_attention_weights = F.softmax(self.feature_attention(feature_input), dim=1)
        scaled_features = feature_input * feature_attention_weights
        
        # Concatenate all features
        joined_features = torch.cat([line_output, variable_output, value_output, scaled_features], dim=1)
        
        # Dense layers
        x = F.relu(self.dense_a(joined_features))
        x = self.dropout_a(x)
        
        x = F.relu(self.dense_b(x))
        x = self.dropout_b(x)
        
        # Final output
        output = torch.sigmoid(self.output_layer(x))
        
        return output.squeeze(-1)


def create_pytorch_model(line_shape: Tuple[int, int, int],
                        variable_shape: Tuple[int, int, int],
                        value_shape: Tuple[int, int, int],
                        feature_shape: Tuple[int, int],
                        **hyperparams) -> PyTorchMlModel:
    """Create PyTorch model with given hyperparameters"""
    return PyTorchMlModel(
        line_shape=line_shape,
        variable_shape=variable_shape,
        value_shape=value_shape,
        feature_shape=feature_shape,
        **hyperparams
    )


def get_model_summary(model: PyTorchMlModel, 
                     line_shape: Tuple[int, int, int],
                     variable_shape: Tuple[int, int, int],
                     value_shape: Tuple[int, int, int],
                     feature_shape: Tuple[int, int]) -> str:
    """Get model summary similar to Keras model.summary()"""
    
    # Create dummy inputs for testing
    batch_size = 1
    dummy_line = torch.randn(batch_size, line_shape[1], line_shape[2])
    dummy_variable = torch.randn(batch_size, variable_shape[1], variable_shape[2])
    dummy_value = torch.randn(batch_size, value_shape[1], value_shape[2])
    dummy_features = torch.randn(batch_size, feature_shape[1])
    
    # Get model info
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    
    summary = f"Model: PyTorchMlModel\n"
    summary += f"Total params: {total_params:,}\n"
    summary += f"Trainable params: {trainable_params:,}\n"
    summary += f"Non-trainable params: {total_params - trainable_params:,}\n"
    summary += f"Input shapes:\n"
    summary += f"  - Line: {line_shape}\n"
    summary += f"  - Variable: {variable_shape}\n"
    summary += f"  - Value: {value_shape}\n"
    summary += f"  - Features: {feature_shape}\n"
    
    return summary
>>>>>>> pytorch_migration:experiment/ml_model.py
