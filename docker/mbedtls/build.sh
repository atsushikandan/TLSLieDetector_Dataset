#!/bin/bash

# versions=(2.28.0 2.28.1 2.28.2 2.28.3 2.28.4 3.0.0 3.1.0 3.2.0 3.2.1 3.3.0 3.4.0 3.4.1)
versions=(3.4.1)

i=0
while [[ i -lt ${#versions[*]} ]]; do
      docker compose --env-file ../build.env build \
      --build-arg VERSION=${versions[$i]} \
      mbedtls
      ((i=i+1))
done

# development branch
docker compose --env-file ../build.env build mbedtls-dev
