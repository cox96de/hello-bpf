#!/bin/bash
set -e
dirs=( $(find . -maxdepth 1 -type d -name '[0-9]*') )

for dir in "${dirs[@]}"; do
  echo "Entering directory $dir"
  cd "$dir" || continue
  make generate
  make build
  make test
  cd ..
done