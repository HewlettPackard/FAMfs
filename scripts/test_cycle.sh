#!/bin/bash
$mpirun $mpi_hosts ${all_n} $mpi_ppn 1 $oMPIchEnv /bin/bash -c "${SCRIPT_DIR}/cleanup.sh"

((tVERBOSE)) && echo "$mpirun $mpi_hosts $AllNodes $mpi_ppn 1 $oMPIchEnv /bin/bash -c \"ulimit -s 1024; $SRV_BIN ${SRV_OPT}\" 2>>$MPI_LOG 1>>$SRV_LOG"
echo "Starting unifycrd..."
$mpirun $mpi_hosts $AllNodes $mpi_ppn 1 $oMPIchEnv /bin/bash -c "ulimit -s 1024; $SRV_BIN ${SRV_OPT}" 2>>$MPI_LOG 1>>$SRV_LOG &
pid=$!

((waiting=0))
((_dt=2)) # Check every 2 sec
echo -n "Waiting for the servers to come up"
for hst in ${AllNodes//,/$IFS}; do
  while
    if ((waiting > 60000))
    then
        echo "***ERROR: Server start timeout" >> $SRV_LOG
        exit 1
    fi
    ((waiting % 30 == 0)) && echo -n "."
    if ((waiting > 0))
    then
        sleep $_dt
    fi
    ((waiting += _dt))
    ssh -q "${hst}" exit || { echo "Cannot ssh to ${hst}"; exit 1; }
    ssh -q ${hst} test "! -e /tmp/unifycrd.running.*"
  do
    :
  done
done
echo

echo "### $DSC" >>$TEST_LOG
echo "### $DSC" >>$MPI_LOG
echo "### $DSC" >>$SRV_LOG
TEST_BASH_ARG="ulimit -s 1024; ulimit -c unlimited; $TEST_BIN ${TEST_OPTS}"
((tVERBOSE)) && echo "$mpirun $cMPImap $mpi_hosts $Clients $mpi_ppn $Ranks $oMPIchEnv /bin/bash -c ""${TEST_BASH_ARG}"" 2>>$MPI_LOG 1>>$TEST_LOG"
echo "Starting test..."
$mpirun $cMPImap $mpi_hosts $Clients $mpi_ppn $Ranks $oMPIchEnv /bin/bash -c "${TEST_BASH_ARG}" 2>>$MPI_LOG 1>>$TEST_LOG

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
echo "Stopping servers"
kill -INT $pid
while ps -p $pid 2>/dev/null 1>/dev/null; do
    echo "Waiting for unifycrd to exit"
    sleep 10
    kill -INT $pid 2>/dev/null 1>/dev/null
done
exit $sts
