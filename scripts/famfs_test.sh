#!/bin/bash
SCRIPT_DIR=${SRC_DIR}/FAMfs/scripts
export SCRIPT_DIR
. ${SCRIPT_DIR}/setup-env.sh

function run-all() { mpirun --hosts ${all_n} -ppn 1 /bin/bash -c "$@"; }
function run-cln() { mpirun --hosts ${all_c} -ppn 1 /bin/bash -c "$1 $2 $3 $4 $5 $6"; }
function run-srv() { mpirun --hosts ${all_h} -ppn 1 /bin/bash -c "$1 $2 $3 $4 $5 $6"; }
export -f run-all
export -f run-cln
export -f run-srv

function count() {
    IFS=","
    __NC=$(echo $1 | wc -w)
    unset IFS;
    echo $__NC
}

function getval() {
    __str=$1
    ((__n = ${#__str} - 1))
    __val=${__str:0:$__n}
    __sfx=${__str:$__n:1}
    case $__sfx in
    'k' | 'K') ((__val = __val*1024)) ;;
    'm' | 'M') ((__val = __val*1024*1024)) ;;
    'g' | 'G') ((__val = __val*1024*1024*1024)) ;;
    '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9') ((__val=__str)) ;;
    esac
    echo $__val
}

function make_list() {
    a=(`echo "$1" | tr ',' ' '`)
    if ((${#a[*]} == 0 || $2 <= 0)); then
        echo ""
        return;
    fi
    list=""
    for ((i = 0; i < $2 && i < ${#a[*]}; i++)); do
        list="$list${a[$i]},"
    done
    list=${list:0:((${#list}-1))}
    echo $list
}

function strip_hostname() {
# Example: Strip '-ib' from 'Node101-ib'
  echo ${1%-[a-z]*}
}

function get_suffix() {
# Return node suffix, i.e. '-ib' for 'node101-ib'
  local cl=${1%%,*}
  local stripped_cl=$(strip_hostname $cl)
  local n=${#stripped_cl}
  echo ${cl:n}
}

function get_myhostname() {
# Usage: get_myhostname "Client_nodes"
  local suffix=$(get_suffix "$1")
  local hn=$(hostname)
  [ -z "$suffix" ] || hn+="-${suffix}"
  echo $hn
}

function add_mynode() {
# Add my node to a list
  local n nodes my found=false
  IFS=','
  nodes=($@)
  my=$(get_myhostname "${nodes[0]}")
  for n in ${nodes[@]}; do
    [[ "$my" == "$n" ]] && { found=true; break; }
  done
  $found || nodes+=("$my")
  echo "${nodes[*]}"
  unset IFS
}

OPTS=`getopt -o I:i:S:C:R:b:s:nw:r:W:c:vqVE:p:F:m: -l iter-srv:,iter-cln:,servers:,clients:,ranks:,block:,segment:,n2n,writes:,reads:,warmup:,cycles:,verbose,sequential:verify,extent:,lf_progress:,fams:,md: -n 'parse-options' -- "$@"`
if [ $? != 0 ] ; then echo "Failed parsing options." >&2 ; exit 1 ; fi
#echo "$OPTS"
eval set -- "$OPTS"

all_h=""
all_c=""
if command -v squeue; then
  MPIchEnv="-genv MPICH_NEMESIS_NETMOD mxm"
  nodes=($(squeue -u $USER -o %P:%N -h | cut -d':' -f 2))
  parts=($(squeue -u $USER -o %P:%N -h | cut -d':' -f 1))
  for ((i = 0; i < ${#parts[*]}; i++)) do
    nlist=${nodes[$i]}
    if [[ "$nlist" =~ "[" ]]; then
        #some sort of range, list or combination of the two
        base=${nlist%%[*}
        #split into ranges separated by space
        spec=`echo ${nlist##$base} | tr -d [] | tr , ' '`
        nodes=""
        for range in $spec; do
            #process range
            beg=${range%-*}
            len=${#beg}
            ((rbeg = beg))
            ((rend = ${range#*-}))
            if ((rend > rbeg)); then
                #range
                for ((j = rbeg; j <= rend; j++)); do
                    node=`printf "%s%0*d-ib," $base $len $j`
                    nodes="$nodes$node"
                done
            else
                #just one node
                nodes="$nodes$base$range-ib,"
            fi
        done
    else
        #single node
        nodes="$nlist-ib,"
    fi
    nodes=${nodes:0:((${#nodes}-1))}
    if [[ "${parts[$i]}" == *"ionode"* ]]; then
        all_h="$all_h$nodes,"
    else
        all_c="$all_c$nodes,"
    fi
  done
  all_h=${all_h:0:((${#all_h}-1))}
  all_c=${all_c:0:((${#all_c}-1))}
  echo "Allocated Servers: $all_h"
  echo "Allocated Clients: $all_c"
else
  MPIchEnv=""
fi
export MPI_LOG=${PWD}/mpi.log
export TEST_LOG=${PWD}/test.log
export SRV_LOG=${PWD}/server.log

### DEFAULTS ###
ExtSize="1G"
lfProgress="manual"
fams=""
oSERVERS="$all_h"
oCLIENTS="$all_c"
oRANKS="1,2,4,8,16"
oBLOCK="1G"
oSEGMENT="1"
oWRITES="4K,64K,128K,1M"
oREADS=""
oWARMUP="0"
oMdServers=""

oVERBOSE=0
oN2N=0
oSEQ=0
oVFY=0

cycles=1

declare -a SrvIter
declare -a ClnIter

while true; do
  case "$1" in
  -v | --verbose )   oVERBOSE=1; shift ;;
  -n | --n2n)        oN2N=1; shift ;;
  -q | --sequential) oSEQ=1; shift ;;
  -S | --servers)    oSERVERS="$2"; shift; shift ;;
  -C | --clients)    oCLIENTS="$2"; shift; shift ;;
  -R | --ranks )     oRANKS="$2"; shift; shift ;;
  -b | --block)      oBLOCK="$2"; shift; shift ;;
  -s | --segment)    oSEGMENT="$2"; shift; shift ;;
  -w | --writes)     oWRITES="$2"; shift; shift ;;
  -W | --warmup)     oWARMUP="$2"; shift; shift ;;
  -r | --reads)      oREADS="$2"; shift; shift ;;
  -c | --cycles)     cycles="$2"; shift; shift ;;
  -i | --iter-cln)   ClnIter=(`echo "$2" | tr ',' ' '`); shift; shift ;;
  -I | --iter-srv)   SrvIter=(`echo "$2" | tr ',' ' '`); shift; shift ;;
  -V | --verify)     oVFY=1; shift ;;
  -E | --extent)     ExtSize="$2"; shift; shift ;;
  -p | --lf_progress) lfProgress="$2"; shift; shift ;;
  -F | --fams)       fams="$2"; shift; shift ;;
  -m | --md)         oMdServers="$2"; shift; shift ;; # Default: Servers
  -- ) shift; break ;;
  * ) break ;;
  esac
done

if [ -z "$oREADS" ]; then oREADS=$oWRITES; fi
if [ -z "$all_h" ]; then all_h="$oSERVERS"; fi
if [ -z "$all_c" ]; then all_c="$oCLIENTS"; fi

export all_h
export all_c
export hh="${oSERVERS}"
export cc="${oCLIENTS}"
ns=$(count $hh)
nc=$(count $cc)
IFS=","

((i = 0))
((max_ranks = 0))
for r in $oRANKS; do RANK[$i]=$r; if ((RANK[i] > max_ranks)); then ((max_ranks = RANK[i])); fi; ((i++)); done

((i = 0))
((max_tx = 0))
for w in $oWRITES; do TXSZ[$i]=$(getval $w); if ((TXSZ[i] > max_tx)); then ((max_tx = TXSZ[i])); fi; ((i++)); done

((i = 0))
for r in $oREADS; do RDSZ[$i]=$(getval $r); ((i++)); done

blksz=$(getval $oBLOCK)
wup=$(getval $oWARMUP)
seg=$(getval $oSEGMENT)
extsz=$(getval $ExtSize)

# Real FAM or emulation?
oData=""
if [[ -z "$fams" ]]; then
  oFAMs=""
  # Pass the number of data chunks option if zhpe driver is loaded
  [ -d /sys/module/zhpe ] && oData="-n"
else
 oFAMs="-F $fams"
fi

if ((!${#SrvIter[*]})); then SrvIter[0]=$ns; fi
if ((!${#ClnIter[*]})); then ClnIter[0]=$nc; fi

unset IFS
opt=""

if ((oSEQ)); then seq="-S 1"; else seq=""; fi
((err=0))
for ((si = 0; si < ${#SrvIter[*]}; si++)); do
    export Servers=`make_list "$hh" ${SrvIter[$si]}`
    ns=`count $Servers`
    [ -z "$oData" ] || oData="${oData::2} $ns"
    mdExclusive=""
    if [ -z "$oMdServers" ]; then
        mdServers="$Servers"
    else
        mdServers="$oMdServers"
        # Prepare list of MD nodes which are not in Servers
        declare -A _t
        mdExclusive=()
        IFS=','
        for _e in $Servers; do ((++_t['$_e'])); done
        for _e in $oMdServers; do ((_t['$_e']==0)) && mdExclusive+=($_e); done
        ((${#mdExclusive}>0)) && mdExclusive="${mdExclusive[*]}"
        unset IFS
        unset _t
    fi

    for ((ci = 0; ci < ${#ClnIter[*]}; ci++)); do
        export Clients=`make_list "$cc" ${ClnIter[$ci]}`
        AllNodes="$Servers,$Clients"
        [ -z "$mdExclusive" ] || AllNodes+=",$mdExclusive"
        all_n=$(add_mynode "$AllNodes") # Force my node included
        echo "=== $Clients -> $Servers [Meta: $mdServers] ===" >> $TEST_LOG
        nc=`count $Clients`

        for ((i = 0; i < ${#RANK[*]}; i++)); do
            for ((j = 0; j < ${#TXSZ[*]}; j++)); do
                dsc="[$nc*${RANK[$i]}]->$ns Block=$blksz Segments=$seg"
                dsc="$dsc Writes=${TXSZ[$j]}"
                if [ -z "${RDSZ[$j]}" ]; then 
                    reads="-w"
                    dsc="$dsc <no reads>"
                else
                    if ((RDSZ[$j] < 0)); then
                        reads="-w"
                        dsc="$dsc <no reads>"
                    else
                        reads="-r ${RDSZ[$j]}"
                        dsc="$dsc Reads=${RDSZ[$j]}"
                    fi
                fi
                if [ -z "$seq" ]; then 
                    dsc="$dsc RANDOM"
                else
                    dsc="$dsc SEQ"
                fi
                if ((oN2N)); then 
                    ptrn="-p 1"
                    dsc="$dsc N-to-N"
                else
                    ptrn="-p 0"
                    dsc="$dsc N-to-1"
                fi
                if ((wup == 0)); then 
                    wu="" 
                    dsc="$dsc <no warmup>"
                else 
                    wu="-W $wup"
                    dsc="$dsc WARMUP=$wup"
                fi
                if ((oVFY)); then
                    dsc="$dsc with VFY"
                    opt="$opt -V"
                fi
                if ((oVERBOSE)); then
                    opt="$opt -v1"
                fi
                for ((k = 0; k < cycles; k++)); do
                    ((mem = (nc*RANK[i]*seg*blksz + nc*RANK[i]*wup)/ns))
                    ((mem = (mem/1024/1024/1024 + 1)*1024*1024*1024))
                    export BLK="-b $blksz"
                    export SEG="-s $seg"
                    export WSZ="-t ${TXSZ[$j]}"
                    export RSZ="$reads"
                    export WUP="$wu"
                    export PTR="$ptrn"
                    export SEQ="$seq"
                    export OPT="$opt"
                    export DSC="$dsc"
                    export Ranks="${RANK[$i]}"
                    export AllNodes
                    export all_n
                    export MEM=$mem
                    export DSC="$dsc"
                    export extsz
                    export lfProgress
                    export oFAMs
                    export oData
                    export mdServers
                    source ${SCRIPT_DIR}/test-env
                    ((kk = k + 1))
                    echo "Starting cycle $kk of: $DSC"
                    if ${SCRIPT_DIR}/test_cycle.sh; then
                        echo "Finished OK"
                    else
                        ((err++))
                        echo "Finished with ERRORS"
                    fi
                done
            done
        done
        echo "===" >> $TEST_LOG
    done
done
echo "Error count: $err"
