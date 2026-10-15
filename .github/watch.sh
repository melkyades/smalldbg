#!/usr/bin/env bash
# Runs a command. When it is still running after LIMIT seconds, prints the
# stacks of its threads, and of the processes it started, then stops them all.
#
#   .github/watch.sh <limit seconds> <command> [args...]
set -u

limit=$1
shift

"$@" &
pid=$!

for ((elapsed = 0; elapsed < limit; elapsed++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid"
        exit $?
    fi
    sleep 1
done

echo "::error::$1 was still running after ${limit}s; the stacks follow"
for p in "$pid" $(pgrep -P "$pid"); do
    echo "=== process $p"
    ps -o pid,stat,command -p "$p"
    # spindump shows the kernel frames too, for a process that waits in a
    # system call. It takes the task port of the process, so it runs as
    # root, which needs no authorization, and is stopped if it waits anyway.
    sudo -n perl -e 'alarm 60; exec @ARGV' spindump "$p" 1 -onlyTarget -stdout \
        -noProcessingWhileSampling 2>&1 | sed -n '/^Process:/,$p' | head -100
done
# What the daemons that grant task ports said while the command waited.
sudo -n log show --last "$((limit + 30))s" --style compact \
    --predicate 'process == "authd" OR process == "taskgated" OR process == "taskgated-helper"' \
    2>&1 | tail -80
kill -9 $(pgrep -P "$pid") "$pid" 2>/dev/null
exit 1
