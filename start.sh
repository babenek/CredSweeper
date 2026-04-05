#!/usr/bin/env bash

set -ex

export JOBS=16
#export TUNER=--tuner
export TUNER=--epochs\ 2
export CREDSWEEPER_DIR=/home/babenek/q/CredSweeper/litert
export CREDDATA_DIR=/home/babenek/w/DataCred-test

export PYTHONPATH=/home/babenek/q/CredSweeper/litert:"${PYTHONPATH}"

bash experiment/main.sh | tee $(date +%Y%m%d_%H%M%S).log

# check train
python -m credsweeper --path ./tests/samples/ --color --no-stdout
