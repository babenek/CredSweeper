#!/usr/bin/env bash

set -ex

export JOBS=16
#export TUNER=--tuner
export CREDSWEEPER_DIR=/home/babenek/q/CredSweeper/litert
export CREDDATA_DIR=/home/babenek/q/DataCred/quick

export PYTHONPATH=/home/babenek/q/CredSweeper/pytorch_migration:"${PYTHONPATH}"

bash experiment/main.sh | tee $(date +%Y%m%d_%H%M%S).log

# check train
.venv/bin/python -m credsweeper --path ./tests/samples/ --color --no-stdout
