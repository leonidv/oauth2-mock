#!/usr/bin/env bash

set -e

VERSION=$(cargo pkgid | cut -d "#" -f2)

cargo build --release
docker build . -t leonidv/oauth2-mock:latest -t leonidv/oauth2-mock:$VERSION
docker push -a leonidv/oauth2-mock

