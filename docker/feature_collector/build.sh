#!/bin/bash
VERSION=3.11-slim-bookworm

docker compose --env-file ../build.env build \
    --build-arg VERSION=${VERSION} \
    feature_collector
