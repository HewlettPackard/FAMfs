#!/bin/bash
run-all ${SCRIPT_DIR}/cleanup.sh

echo "Starting unifycrd with $MEM of memory"
mpirun --hosts $AllNodes -ppn 1 $MPIchEnv /bin/bash -c 'ulimit -s 1024; unifycrd' 2>>$MPI_LOG 1>>$SRV_LOG &
pid=$!

((waiting=0))
((_dt=2)) # Check every 2 sec
echo -n "Waiting for the servers to come up"
while
    if ((waiting > 600))
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
    ! ls /tmp/unifycrd.running.* 1>/dev/null 2>&1
do
    :
done

echo "### $DSC" >>$TEST_LOG
echo "### $DSC" >>$MPI_LOG
echo "### $DSC" >>$SRV_LOG
echo "Starting test..."
#echo "test_prw_static -f /tmp/mnt/abc $BLK $SEG $WSZ $RSZ $PTR $WUP $SEQ -D 0 -u 0"
mpirun --hosts $Clients -ppn $Ranks /bin/bash -c 'ulimit -s 1024; ulimit -c unlimited; test_prw_static -f /tmp/mnt/abc $BLK $SEG $WSZ $RSZ $PTR $WUP $SEQ -D 0 -u 0 $OPT' 2>>$MPI_LOG 1>>$TEST_LOG

if (($? == 0))
then
    echo "### OK" >>$TEST_LOG
    echo "Test completed successfully"
    sts=0
else
    echo "### ERRORS" >>$TEST_LOG
    echo "Test failed"
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
