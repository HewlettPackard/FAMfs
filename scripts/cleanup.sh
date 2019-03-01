#!/bin/bash

#kill unifycrd if it is still running
tmp=$(pgrep -af "unifycrd") && pid=$(echo $tmp | cut -f1 -d' ') && kill $pid
rm -rf /tmp/socket*
rm -rf /dev/shm/*
rm -rf /tmp/*.running.*
