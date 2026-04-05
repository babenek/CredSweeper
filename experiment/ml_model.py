from typing import Any, Optional

import keras_tuner as kt
from tensorflow.keras.layers import Dense, LSTM, Input, Concatenate, Dropout
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
from tensorflow.python.keras.layers import ReLU, Softmax, Multiply
from tensorflow.python.keras.metrics import BinaryAccuracy, Precision, Recall

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
        line_lstm_dropout_rate = self.get_hyperparam("line_lstm_dropout_rate", hp)
        variable_lstm_dropout_rate = self.get_hyperparam("variable_lstm_dropout_rate", hp)
        value_lstm_dropout_rate = self.get_hyperparam("value_lstm_dropout_rate", hp)
        dense_a_drop = self.get_hyperparam("dense_a_drop", hp)
        dense_b_drop = self.get_hyperparam("dense_b_drop", hp)

        line_input = Input(batch_shape=(1, MlValidator.MAX_LEN, self.line_shape[2]), name="line_input", dtype=self.d_type)
        line_lstm_fw = LSTM(units=self.line_shape[1],
                            dtype=self.d_type,
                            dropout=line_lstm_dropout_rate,
                            recurrent_dropout=0,
                            return_sequences=False,
                            go_backwards=False,
                            unroll=False,
                            name="line_lstm_fw",
                            )
        line_lstm_bw = LSTM(units=self.line_shape[1],
                            dtype=self.d_type,
                            dropout=line_lstm_dropout_rate,
                            recurrent_dropout=0,
                            return_sequences=False,
                            go_backwards=True,
                            unroll=False,
                            name="line_lstm_bw",
                            )

        variable_input = Input(batch_shape=(1, ML_HUNK, self.variable_shape[2]), name="variable_input", dtype=self.d_type)
        variable_lstm_fw = LSTM(units=self.variable_shape[1],
                                dtype=self.d_type,
                                dropout=variable_lstm_dropout_rate,
                                recurrent_dropout=0,
                                return_sequences=False,
                                go_backwards=False,
                                unroll=False,
                                name="variable_lstm_fw",
                                )
        variable_lstm_bw = LSTM(units=self.variable_shape[1],
                                dtype=self.d_type,
                                dropout=variable_lstm_dropout_rate,
                                recurrent_dropout=0,
                                return_sequences=False,
                                go_backwards=True,
                                unroll=False,
                                name="variable_lstm_bw",
                                )

        value_input = Input(batch_shape=(1, ML_HUNK, self.value_shape[2]), name="value_input", dtype=self.d_type)
        value_lstm_fw = LSTM(units=self.value_shape[1],
                             dtype=self.d_type,
                             dropout=value_lstm_dropout_rate,
                             recurrent_dropout=0,
                             return_sequences=False,
                             go_backwards=False,
                             unroll=False,
                             name="value_lstm_fw",
                             )
        value_lstm_bw = LSTM(units=self.value_shape[1],
                             dtype=self.d_type,
                             dropout=value_lstm_dropout_rate,
                             recurrent_dropout=0,
                             return_sequences=False,
                             go_backwards=True,
                             unroll=False,
                             name="value_lstm_bw",
                             )

        feature_input = Input(shape=(self.feature_shape[1],), name="feature_input", dtype=self.d_type)
        feature_attention = Dense(self.feature_shape[1], activation=Softmax(), use_bias=False,
                                  name="feature_attention")(feature_input)
        x_scaled = Multiply(name="feature_multiply")([feature_input, feature_attention])

        joined_features = Concatenate()([
            line_lstm_fw(line_input),
            line_lstm_bw(line_input),
            variable_lstm_fw(variable_input),
            variable_lstm_bw(variable_input),
            value_lstm_fw(value_input),
            value_lstm_bw(value_input),
            x_scaled
        ])

        # 3 bidirectional + features
        dense_units = 2 * MlValidator.MAX_LEN + 2 * 2 * ML_HUNK + self.feature_shape[1]
        # check after model compilation. Should be matched the combined size.

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
        model.layers[0].batch_input_shape = (1, ML_HUNK, self.value_shape[2])
        return model
