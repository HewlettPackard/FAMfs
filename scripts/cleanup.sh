#!/bin/bash

while pgrep "$TEST_BIN" > /dev/null; do sleep 1; done

#kill unifycrd if it is still running
tmp=$(pgrep -af "unifycrd ${SRV_OPT}") && pid=$(echo $tmp | cut -f1 -d' ') && kill $pid
rm -rf /dev/shm/*
rm -f /tmp/*.running.* 2>/dev/null
find /tmp -type f -name 'famfs.log*' -size +200M -delete 2>/dev/null

while pgrep "unifycrd" > /dev/null; do sleep 1; done
