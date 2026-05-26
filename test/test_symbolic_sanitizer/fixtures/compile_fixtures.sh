#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
gcc -g -O0 -fno-inline -o "$DIR/two_branches" "$DIR/two_branches.c"
echo "built $DIR/two_branches"
