#!/bin/bash

test_description="Shut down famfsd"

. $(dirname $0)/sharness.sh

test_expect_success "Stop famfsd" '
    famfsd_stop_daemon
    process_is_not_running famfsd 5
'

test_done
