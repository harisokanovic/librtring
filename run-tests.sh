#!/bin/bash
set -euo pipefail

readonly TEMP_DIR=$(mktemp -d "/tmp/librtring-tests-XXXXXXX")
test_count=0
fail_count=0

function cleanup() {
    local exitCode="$?"
    set +e

    if [ "$exitCode" == "0" ]; then
        if [ "$test_count" == 0 -o "$fail_count" != 0 ]; then
            exitCode=1
        fi
    fi

    if [ -e "$TEMP_DIR" ]; then
        rm -Rf "$TEMP_DIR"
    fi

    echo "$test_count tests ran, $fail_count tests failed, exitCode=$exitCode"

    exit "$exitCode"
}

trap cleanup EXIT

while [ $# -gt 0 ]; do
    test_name="$1"
    shift 1

    # TODO anonymous buffer (--ring-file "") presently fails, mirror
    #  buffer doesn't work

    rm -f "$TEMP_DIR/new_buf"
    echo -n "" > "$TEMP_DIR/empty_buf"
    dd of="$TEMP_DIR/1B_buf" if=/dev/zero bs=1 count=1 2>/dev/null
    dd of="$TEMP_DIR/3B_buf" if=/dev/zero bs=3 count=1 2>/dev/null
    dd of="$TEMP_DIR/1M_buf" if=/dev/zero bs=1M count=1 2>/dev/null

    for buf_path in "$TEMP_DIR/new_buf" "$TEMP_DIR/empty_buf" "$TEMP_DIR/1B_buf" "$TEMP_DIR/3B_buf" "$TEMP_DIR/1M_buf"; do
        test_count=$(( "$test_count" + 1 ))

        test_cmd="./$test_name --ring-file $buf_path"

        rm -f "$TEMP_DIR/output"
        if $test_cmd >"$TEMP_DIR/output" 2>&1 </dev/null; then
            echo "$test_cmd: PASS"
        else
            echo "$test_cmd: FAIL"
            cat "$TEMP_DIR/output"
            fail_count=$(( "$fail_count" + 1 ))
        fi
    done
done
