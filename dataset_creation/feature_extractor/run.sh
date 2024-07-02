#!/bin/bash

source ../run.env
mkdir -p "${DATASET_DIR}/feature"

docker compose --env-file ../run.env up
