#!/bin/bash
VERSION=3.11-alpine3.18

docker compose --env-file ../build.env build \
    --build-arg VERSION=${VERSION} \
    faketls
