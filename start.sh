#!/usr/bin/env bash

set -ex

export JOBS=16
#export TUNER=--epochs\ 3
export CREDSWEEPER_DIR=`pwd`
export CREDDATA_DIR=/home/babenek/w/DataCred-oss
export TESTDATA_DIR=/home/babenek/q/DataCred/main

export PYTHONPATH=/home/babenek/q/CredSweeper/litert:"${PYTHONPATH}"

bash experiment/main.sh | tee $(date +%Y%m%d_%H%M%S).log

# check train
python -m credsweeper --path ./tests/samples/ --color --no-stdout
