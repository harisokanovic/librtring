#!/bin/bash

set -x

rtpi_path="$1"

if [ -d "$rtpi_path" ]; then
    export LD_LIBRARY_PATH=".:$rtpi_path/src/.libs/"
    export CFLAGS="-I$rtpi_path/src -L$rtpi_path/src/.libs/"
else
    echo 1>&2 "ERROR: Must specify path to rtpi repo"
fi

set +x
