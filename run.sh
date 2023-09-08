#!/usr/bin/env bash

cd "$(dirname "$0")"

ARCH=$(uname -m)
if [[ "$ARCH" == x86_64* ]]; then
  cd amd64
elif  [[ "$ARCH" == aarch64* ]]; then
  cd arm64
else
  echo "Unsupported architecture: $ARCH"
  exit 1
fi

export XTABLES_LIBDIR=./xtables
export LD_LIBRARY_PATH=./
exec ./ld-linux.so.1 ./nfpanic

