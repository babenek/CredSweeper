from typing import List

import numpy as np
import torch
from sklearn.metrics import f1_score, precision_score, recall_score, log_loss, accuracy_score

from pytorch_model import PyTorchMlModel


def evaluate_pytorch_model(thresholds: dict, model: PyTorchMlModel, x_data: List[np.ndarray], y_label: np.ndarray, device: torch.device = None):
    """Evaluate PyTorch model with printing scores

    Args:
        thresholds: dict of credsweeper thresholds
        model: fitted PyTorch model
        x_data: List of np.arrays. Number and shape depends on model
        y_label: expected result
        device: torch device to run evaluation on
    """
    if device is None:
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    model.eval()
    model.to(device)
    
    # Convert numpy arrays to torch tensors
    line_input = torch.FloatTensor(x_data[0]).to(device)
    variable_input = torch.FloatTensor(x_data[1]).to(device)
    value_input = torch.FloatTensor(x_data[2]).to(device)
    feature_input = torch.FloatTensor(x_data[3]).to(device)
    
    # Get predictions
    with torch.no_grad():
        predictions_proba = model(line_input, variable_input, value_input, feature_input)
        predictions_proba = predictions_proba.cpu().numpy()
    
    # Evaluate with different thresholds
    for name, threshold in thresholds.items():
        predictions = (predictions_proba > threshold).astype(int)
        accuracy = accuracy_score(y_label, predictions)
        precision = precision_score(y_label, predictions, zero_division=0)
        recall = recall_score(y_label, predictions, zero_division=0)
        loss = log_loss(y_label, predictions_proba)
        f1 = f1_score(y_label, predictions, zero_division=0)
        print(
            f"{name}: {threshold:0.6f}, "
            f"accuracy: {accuracy:0.6f}, "
            f"precision:{precision:0.6f}, "
            f"recall: {recall:0.6f}, "
            f"loss: {loss:0.6f}, "
            f"F1:{f1:0.6f}",
            flush=True)


# Alias for backward compatibility
evaluate_model = evaluate_pytorch_model
