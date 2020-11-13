#!/bin/bash
#
# Perform some initial setup for the test suite. This is not
# implemented as a sharness test because leaving a process running
# behind (i.e. famfsd) causes tap-driver.sh to hang waiting for
# the process to exit.
#

# Print TAP plan
echo 1..1

#
# Create temporary directories to be used as a common mount point and a
# common metadata directory across multiple tests. Save the value to a
# script in known location that later test scripts can source.
#
export UNIFYCR_MOUNT_POINT=$(mktemp -d)
export UNIFYCR_META_DB_PATH=$(mktemp -d)

#
# Source test environment first to pick up UNIFYCR_TEST_RUN_SCRIPT
#
. $(dirname $0)/sharness.d/00-test-env.sh

cat >"$UNIFYCR_TEST_RUN_SCRIPT" <<-EOF
export UNIFYCR_MOUNT_POINT=$UNIFYCR_MOUNT_POINT
export UNIFYCR_META_DB_PATH=$UNIFYCR_META_DB_PATH
EOF

. $(dirname $0)/sharness.d/01-unifycr-settings.sh
. $(dirname $0)/sharness.d/02-functions.sh

#
# Start the UnifyCR daemon after killing and cleanup up after any previously
# running instance.
#
famfsd_stop_daemon
famfsd_cleanup
famfsd_start_daemon

#
# Make sure famfsd starts whithin 15 seconds
#
if ! process_is_running famfsd 15; then
   echo not ok 1 - daemon is not started
   exit 1
fi

#
# Make sure famfsd stays running for 5 seconds to catch cases where
# it dies during initialization.
#
if process_is_not_running famfsd 5; then
    echo not ok 1 - famfsd is not running
    exit 1
else
    echo ok 1 - famfsd running
fi

exit 0
