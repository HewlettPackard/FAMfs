#!/bin/bash
TESTCYCLE_PID_FN="/tmp/testcycle.pid"
sts=1

function start_server() {
  # always remove files that server creates
  pdsh -w "$AllNodes" rm -f '/tmp/unifycrd.running.*'
  pdsh -w "$Servers" find /tmp -type f -regex '/tmp/EDR.[0-9]+-[0-9]+.[0-9]+' -exec 'rm -f {} \;'
  # start Server
  ((tVERBOSE)) && echo "$mpirun $mpi_hosts $AllNodes $mpi_ppn 1 $oMPIchEnv /bin/bash -c \"ulimit -s 1024; $SRV_BIN ${SRV_OPT}\" 2>>$MPI_LOG 1>>$SRV_LOG"
  echo "Starting unifycrd..."
  $mpirun $mpi_hosts $AllNodes $mpi_ppn 1 $oMPIchEnv /bin/bash -c "ulimit -s 1024; $SRV_BIN ${SRV_OPT}" 2>>$MPI_LOG 1>>$SRV_LOG &
  pid=$!
  echo $pid > $TESTCYCLE_PID_FN
  # wait for running servers
  ((_dt=2)) # Check every 2 sec
  echo -n "Waiting for the servers to come up"
  for hst in ${AllNodes//,/$IFS}; do
    ((waiting=0))
    while
      if ((waiting > 6000))
      then
          echo "***ERROR: Server start timeout" >> $SRV_LOG
          exit 1
      fi
      ((waiting % 30 == 0)) && echo -n "."
      ((waiting > 0))&& sleep $_dt
      ((waiting += _dt))
      ssh -q "${hst}" exit || { echo "Cannot ssh to ${hst}"; exit 1; }
      let _nf=$(ssh -q "${hst}" find /tmp -maxdepth 1 -type f -name 'unifycrd.running.*' 2>/dev/null | wc -l)
      ((_nf>1))&& { echo "Please clean ${hst}:/tmp/"; exit 1; }
      ((_nf==0))
    do
      :
    done
  done
  echo
  echo "### $DSC" >>$MPI_LOG
  echo "### $DSC" >>$SRV_LOG
}

function stop_server() {
  pid=$(cat $TESTCYCLE_PID_FN)
  echo "Stopping servers ($pid)"
  kill -INT $pid
  while ps -p $pid 2>/dev/null 1>/dev/null; do
    echo "Waiting for unifycrd to exit"
    sleep 6
    kill -INT $pid 2>/dev/null 1>/dev/null
  done
}

function run_test() {
  echo "### $DSC" >>$TEST_LOG
  ((FAMFS_DO_STATS))&& oMPIchEnv="$oMPIchEnv -x FAMFS_DO_STATS"
  TEST_BASH_ARG="$cNUMAshell $TEST_BIN $TEST_OPTS"
  ((tVERBOSE)) && echo "$mpirun $cMPImap $mpi_hosts $Clients $oMPIchEnv /bin/bash -c \"$TEST_BASH_ARG\" 2>>$MPI_LOG 1>>$TEST_LOG"
  echo "Starting test..."
  $mpirun $cMPImap $mpi_hosts $Clients $oMPIchEnv /bin/bash -c "$TEST_BASH_ARG" 2>>$MPI_LOG 1>>$TEST_LOG

  if (($? == 0))
  then
    echo "### OK" >>$TEST_LOG
    echo "Test completed successfully"
    sts=0
  else
    echo "### ERRORS" >>$TEST_LOG
    echo "Test failed"
    # sleep 10000
    sts=1
  fi
}

# restart Server
if ((iPattern==-1)); then
  echo "Restarting Server with CONF=$UNIFYCR_CONFIGFILE ..."
  stop_server
  start_server
  sts=0
  echo "    Server restarted" >>$TEST_LOG
fi

# start Server
if ((tStartServer)); then
  $mpirun $mpi_hosts ${all_n} $mpi_ppn 1 $oMPIchEnv /bin/bash -c "${SCRIPT_DIR}/cleanup.sh"
  start_server
fi

# run test
if ((iPattern>=0)); then
  run_test
fi

# stop Server
if ((tStopServer)); then
  stop_server
fi

exit $sts
