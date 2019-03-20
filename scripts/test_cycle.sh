#!/bin/bash
run-all `pwd`/cleanup.sh

echo "Starting unifycrd with $MEM of memory"
mpirun --hosts $AllNodes -ppn 1 -genv MPICH_NEMESIS_NETMOD mxm /bin/bash -c 'ulimit -s 1024; unifycrd' 2>>$MPI_LOG 1>>$SRV_LOG &
pid=$!

#echo $LFS_COMMAND
#echo $FAMFS_MDS_LIST

((waiting=0))
while
    if ((waiting > 600))
    then
        echo "***ERROR: Server start timeout" >> $SRV_LOG
        exit 1
    fi
    echo "Waiting for the servers to come up..."
    if ((waiting > 0))
    then
        sleep 10
    fi
    mpirun --hosts $AllNodes -ppn 1 /bin/bash -c 'ls /tmp/uifycrd.running.* && exit 0 || exit 1' 2>/dev/null 1>/dev/null
    sts=$?
    ((waiting += 10))
    ((sts != 0))
do
    :
done

echo "### $DSC" >>$TEST_LOG
echo "### $DSC" >>$MPI_LOG
echo "### $DSC" >>$SRV_LOG
echo "Starting test..."
#echo "/${TEST_BIN}/test_prw_static -f /tmp/mnt/abc $BLK $SEG $WSZ $RSZ $PTR $WUP $SEQ -D 0 -u 0"
mpirun --hosts $Clients -ppn $Ranks /bin/bash -c 'ulimit -s 1024; ulimit -c unlimited; ${TEST_BIN}/test_prw_static -f /tmp/mnt/abc $BLK $SEG $WSZ $RSZ $PTR $WUP $SEQ -D 0 -u 0 $OPT' 2>>$MPI_LOG 1>>$TEST_LOG

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
