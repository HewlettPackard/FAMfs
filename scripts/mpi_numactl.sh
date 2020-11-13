#!/bin/bash

MHZ=$(awk '$2 == "MHz" { print $4 ; exit 0 }' /proc/cpuinfo)

if [[ -n "$MPI_LOCALRANKID" ]]; then
    LOCALRANK=$MPI_LOCALRANKID
    LOCALSIZE=$MPI_LOCALNRANKS
    RANK=$PMI_RANK
else
    LOCALRANK=$OMPI_COMM_WORLD_LOCAL_RANK
    LOCALSIZE=$OMPI_COMM_WORLD_LOCAL_SIZE
    RANK=$OMPI_COMM_WORLD_RANK
fi

NODES=$(numactl -H | awk '$1 == "available:" { print $2 }')
(( NODE = LOCALRANK % NODES )) || true

unset FI_ZHPE_QUEUE_PER_SLICE
unset FI_ZHPE_QUEUE_SLICE
MEM_AFFINITY="-m NODE"
CPU_AFFINITY="-N $NODE"

if grep -q "AMD EPYC 7702" /proc/cpuinfo && (( LOCALSIZE <= 64 )); then
    (( CPN = 64 / NODES ))
    (( S = NODE * CPN ))
    (( E = S + CPN - 1 ))
    CPU_AFFINITY="-C $S-$E"
fi

if (( NODES == 4 )); then
    case $NODE in

    0) export FI_ZHPE_QUEUE_SLICE=0
	;;

    1) export FI_ZHPE_QUEUE_SLICE=1
	;;

    2) export FI_ZHPE_QUEUE_SLICE=3
	;;

    3) export FI_ZHPE_QUEUE_SLICE=2
	;;

    esac
else
    export FI_ZHPE_QUEUE_SLICE=$((LOCALRANK & 3))
fi

ulimit -c unlimited

# echo HOST $HOSTNAME RANK $PMIX_RANK PID $$ $MHZ MHz SLICE $FI_ZHPE_QUEUE_SLICE \
#    numactl -m $NODE $CPU_AFFINITY

exec numactl -m $NODE $CPU_AFFINITY -- $@
