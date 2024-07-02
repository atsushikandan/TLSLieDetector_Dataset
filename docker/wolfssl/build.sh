#!/bin/bash

# versions=(5.5.4 5.6.0)
versions=(5.6.0)

i=0
while [[ i -lt ${#versions[*]} ]]; do
      docker compose --env-file ../build.env build \
      --build-arg VERSION=${versions[$i]} \
      wolfssl
	((i++))
done
