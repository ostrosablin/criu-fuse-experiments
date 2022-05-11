#!/bin/bash
PID=`pgrep hello_ll`
if [ -z "$PID" ]; then
    echo "Target FS not found"
    exit 1
else
    echo "Located a hello_ll FUSE FS @ PID $PID"
fi
for fd in /proc/$PID/fd/*; do
    TARGET=`readlink $fd`
    if [ "$TARGET" == "/dev/fuse" ]; then
        FD="$fd"
        echo "Found a /dev/fuse descriptor @ $fd"
        break
    fi
done
if [ -z "$FD" ]; then
    echo "Unable to find an opened /dev/fuse descriptor @ PID $PID"
    exit 2
fi
exec 3>$FD
echo "Opened a /dev/fuse descriptor from process as FD 4"
kill -9 $PID
echo "Killed original FS process"
echo "Trying to overtake mount with a preserved file descriptor"
ls -l /proc/self/fd
echo $$
exec ./hello_ll -d -s /dev/fd/3
