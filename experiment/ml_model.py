from typing import Any, Optional

import keras_tuner as kt
from keras import Model
from keras.layers import Dense, Input, Concatenate, Dropout, ReLU, Softmax, Multiply, GlobalAveragePooling1D
from keras.optimizers import Adam
from keras.metrics import BinaryAccuracy, Precision, Recall

from credsweeper.common.constants import ML_HUNK
from credsweeper.ml_model.ml_validator import MlValidator


class MlModel(kt.HyperModel):
    d_type = "float32"

    def __init__(self, line_shape: tuple, variable_shape: tuple, value_shape: tuple, feature_shape: tuple, **kwargs):
        self.line_shape = line_shape
        self.variable_shape = variable_shape
        self.value_shape = value_shape
        self.feature_shape = feature_shape
        self.__kwargs = kwargs

    def get_hyperparam(self, param_name: str, hp=None) -> Any:
        if param_name in self.__kwargs:
            param = self.__kwargs.get(param_name)
            if isinstance(param, float):
                print(f"'{param_name}' constant = {param}", flush=True)
                return param
            elif hp and isinstance(param, tuple) and 3 == len(param):
                print(f"'{param_name}' tuning = {param}", flush=True)
                return hp.Float(param_name, min_value=param[0], max_value=param[1], step=param[2])
            else:
                raise ValueError(f"'{param_name}' was not inited well {param} tuner is {hp}")
        else:
            raise ValueError(f"'{param_name}' was not defined during init and tuner is used")

    def build(self, hp: Optional[Any]) -> Model:
        """Get keras model with string and feature input and single binary out"""
        dense_a_drop = self.get_hyperparam("dense_a_drop", hp)
        dense_b_drop = self.get_hyperparam("dense_b_drop", hp)

        # Use fixed sequence lengths for TFLite compatibility
        line_input = Input(shape=(ML_HUNK, self.line_shape[2]), name="line_input", dtype=self.d_type)
        line_pool = GlobalAveragePooling1D(name="line_pool")(line_input)
        line_dense = Dense(units=256, activation=ReLU(), name="line_dense", dtype=self.d_type)(line_pool)

        variable_input = Input(shape=(ML_HUNK, self.variable_shape[2]), name="variable_input", dtype=self.d_type)
        variable_pool = GlobalAveragePooling1D(name="variable_pool")(variable_input)
        variable_dense = Dense(units=128, activation=ReLU(), name="variable_dense", dtype=self.d_type)(variable_pool)

        value_input = Input(shape=(ML_HUNK, self.value_shape[2]), name="value_input", dtype=self.d_type)
        value_pool = GlobalAveragePooling1D(name="value_pool")(value_input)
        value_dense = Dense(units=128, activation=ReLU(), name="value_dense", dtype=self.d_type)(value_pool)

        feature_input = Input(shape=(self.feature_shape[1], ), name="feature_input", dtype=self.d_type)
        feature_attention = Dense(self.feature_shape[1], activation=Softmax(), use_bias=False,
                                  name="feature_attention")(feature_input)
        x_scaled = Multiply(name="feature_multiply")([feature_input, feature_attention])

        joined_features = Concatenate()([line_dense, variable_dense, value_dense, x_scaled])

        # 3 dense branches + features
        dense_units = 256 + 128 + 128 + self.feature_shape[1]

        # first hidden layer
        dense_a = Dense(units=dense_units, activation=ReLU(), name="a_dense", dtype=self.d_type)(joined_features)
        drop_a = Dropout(name="a_drop", rate=dense_a_drop)(dense_a)

        # second hidden layer
        dense_b = Dense(units=dense_units, activation=ReLU(), name="b_dense", dtype=self.d_type)(drop_a)
        drop_b = Dropout(name="b_drop", rate=dense_b_drop)(dense_b)

        dense_final = Dense(units=1, activation='sigmoid', name="prediction", dtype=self.d_type)(drop_b)

        metrics = [BinaryAccuracy(name="binary_accuracy"), Precision(name="precision"), Recall(name="recall")]

        model: Model = Model(inputs=[line_input, variable_input, value_input, feature_input], outputs=dense_final)
        model.compile(optimizer=Adam(), loss='binary_crossentropy', metrics=metrics)
        model.summary(line_length=120, expand_nested=True, show_trainable=True)

        return model
