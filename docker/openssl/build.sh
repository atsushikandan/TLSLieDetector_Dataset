#!/bin/bash

# versions=(0.7 0.8 0.9 0.10 1.0-beta1 1.0 1.1 1.2)
versions=(1.2)
i=0
while [[ i -lt ${#versions[*]} ]]; do
      docker compose --env-file ../build.env build \
      --build-arg VERSION=${versions[$i]} \
      openssl
      ((i=i+1))
done
