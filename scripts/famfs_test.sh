#!/bin/bash
[ -z "$TEST_DIR" ]&& { echo "Error: TEST_DIR is not set!"; exit 1; }
SRC_DIR="${TEST_DIR}/src"
SCRIPT_DIR=${SRC_DIR}/FAMfs/scripts
WRK_DIR=${SCRIPT_DIR}/t
export SCRIPT_DIR
FAMFS_CONF="famfs.conf"

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
        list="$list${a[$i]}$3,"
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
  [ -z "$suffix" ] || hn+="${suffix}"
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

# update key($2) value to $3 for section($1) in $FAMFS_CONF
function update_ini() {
  local s=$1 k=$2 v=$3
  sed -r -i "/^\[$s\]\$/,/^\[/{s/^$k = .* (; .*)\$/$k = $v \1/; t; s/^$k = [^\s]*\$/$k = $v/}" ${FAMFS_CONF}
}

#
# Working DIR
#
mkdir -p ${WRK_DIR}
cd ${WRK_DIR}

#
# Command line
#
OPTS=`getopt -o aA:D:I:i:S:C:R:b:s:nNw:r:W:c:vqQ:VE:u:F:M:m:tx:X:O:U -l adaptive,app:,data:,iter-srv:,iter-cln:,servers:,clients:,ranks:,block:,segment:,n2n,numactl,writes:,reads:,warmup:,cycles:,verbose,sequential,two_passes:,verify,extent:,chunk:,fs_type:,mpi:,md:,tcp,suffix:,extra:,srv_extra:,multi_ep -n 'parse-options' -- "$@"`
if [ $? != 0 ] ; then echo "Failed parsing options." >&2 ; exit 1 ; fi
#echo "$OPTS"
eval set -- "$OPTS"

all_h=""
all_c=""
oMPIchEnv=""
if [[ -d $SLURM_HOME ]] && command -v squeue 1>/dev/null; then
  echo "SLURM: $(command -v squeue)"
  nodes=($(squeue -u $USER -o %P:%N -h | cut -d':' -f 2))
  parts=($(squeue -u $USER -o %P:%N -h | cut -d':' -f 1))
  for ((i = 0; i < ${#parts[*]}; i++)) do
    nlist=${nodes[$i]}
    if [[ "$nlist" =~ "[" ]]; then
        #some sort of range, list or combination of the two
        base=${nlist%%[*}
        #split into ranges separated by space
        spec=`echo ${nlist##$base} | tr -d [] | tr , ' '`
        for range in $spec; do
            #process range
            beg=${range%-*}
            len=${#beg}
            ((rbeg = beg))
            ((rend = 10#${range#*-})) # ignore leading zeroes by explicit 10 base
            ((rend < rbeg)) && ((rend = rbeg))
            #range or single
            nodes=""
            for ((j = rbeg; j <= rend; j++)); do
                node=`printf "%s%0*d" $base $len $j`
                nodes="$nodes$node,"
            done
            # belongs to ionodes?
            if [[ -z $(sinfo -h -n $node -p ionodes -o %D) ]]; then
                all_c="$all_c$nodes"
            else
                all_h="$all_h$nodes"
            fi
        done
    else
        #single node
        nodes="$nlist,"
        all_h="$all_h$nodes"
    fi
  done
  all_h=${all_h:0:((${#all_h}-1))}
  all_c=${all_c:0:((${#all_c}-1))}
  echo "Allocated Servers: $all_h"
  echo "Allocated Clients: $all_c"
fi
export MPI_LOG=${PWD}/mpi.log
export TEST_LOG=${PWD}/test.log
export SRV_LOG=${PWD}/server.log

### DEFAULTS ###
ExtSize="1G"
tstFileName="/tmp/mnt/abc"
oSERVERS="$all_h"
oCLIENTS="$all_c"
oRANKS="1,2,4,8,16"
oBLOCK="1G"
oSEGMENT="1"
oWRITES="4K,128K,1M,16M"
oREADS=""
oWARMUP="0"
oMdServers=""
oVERBOSE=0
oN2N=0
oSEQ=0
oVFY=0
oCycles=1
oDATA=1
oCHUNK="1M"
oNodeSuffix=
oAPP="test_prw_static"
oFStype="FAMfs"
oExtraOpt=
oExtraSrvOpt=
oTCP=0
oMultiEP=0
oAdaptiveRouting=0
oNUMActl=0
oTwoPasses=""

declare -a SrvIter
declare -a ClnIter

while true; do
  case "$1" in
  -a | --adaptive)    ((oAdaptiveRouting=1)); shift ;;
  -A | --app)        oAPP="$2"; shift; shift ;;
  -D | --data)       oDATA="$2"; shift; shift ;;
  -v | --verbose)    ((oVERBOSE++)); shift ;;
  -n | --n2n)        oN2N=1; shift ;;
  -N | --numactl)    oNUMActl=1; shift ;;
  -q | --sequential) oSEQ=1; shift ;;
  -Q | --two-passes) oTwoPasses="$2"; shift; shift ;; # separate writes and reads, set pattern (SEQ,RND)
  -S | --servers)    oSERVERS="$2"; shift; shift ;;
  -C | --clients)    oCLIENTS="$2"; shift; shift ;;
  -R | --ranks )     oRANKS="$2"; shift; shift ;;
  -b | --block)      oBLOCK="$2"; shift; shift ;;
  -s | --segment)    oSEGMENT="$2"; shift; shift ;;
  -w | --writes)     oWRITES="$2"; shift; shift ;;
  -W | --warmup)     oWARMUP="$2"; shift; shift ;;
  -r | --reads)      oREADS="$2"; shift; shift ;;
  -c | --cycles)     oCycles="$2"; shift; shift ;;
  -i | --iter-cln)   ClnIter=(`echo "$2" | tr ',' ' '`); shift; shift ;;
  -I | --iter-srv)   SrvIter=(`echo "$2" | tr ',' ' '`); shift; shift ;;
  -V | --verify)     ((oVFY++)); shift ;;
  -E | --extent)     ExtSize="$2"; shift; shift ;;
  -u | --chunk)      oCHUNK="$2"; shift; shift ;;
  -F | --fs_type)    oFStype="$2"; shift; shift ;;
  -M | --mpi)        oMPIchEnv="$2"; shift; shift ;;
  -m | --md)         oMdServers="$2"; shift; shift ;; # Default: Servers
  -t | --tcp)        oTCP=1; shift ;; # use TCP/IP (sockets) instead of ofi zhpi
  -x | --suffix)     oNodeSuffix="$2"; shift; shift ;;
  -X | --extra)      oExtraOpt="$2"; shift; shift ;; # Pass extra options to the test command line
  -O | --srv_extra)  oExtraSrvOpt="$2"; shift; shift ;; # Pass extra options to FAMFS server
  -U | --multi_ep)   ((oMultiEP=1)); shift ;; # create multiple endpoints in domain (per device)
  -- ) shift; break ;;
  * ) break ;;
  esac
done

if [ -z "$oREADS" ]; then oREADS=$oWRITES; fi
if [ -z "$all_h" ]; then all_h="$oSERVERS"; fi
if [ -z "$all_c" ]; then all_c="$oCLIENTS"; fi

hh="${oSERVERS}"
cc="${oCLIENTS}"
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

nPatterns=1
if [ ! -z "$oTwoPasses" ]; then
  oSEQ=1 # SEQ first
  nPatterns=2
fi

blksz=$(getval $oBLOCK)
wup=$(getval $oWARMUP)
seg=$(getval $oSEGMENT)
extsz=$(getval $ExtSize)
((tVERBOSE=0))
((tIOR=0))

# mpich or ompi?
_s=$(mpirun --version 2>/dev/null)
echo -ne $_s | grep -q "Version:" && ((mpich=1)) || ((mpich=0))
echo -ne $_s | grep -q "Open MPI" && ((ompi=1)) || ((ompi=0))
((mpich==0))&&((ompi==0))&&{ echo "No MPI found!"; exit 1; }
unset _s
((mpich))&& { mpi_hosts="--hosts"; mpi_ppn="--ppn"; }
((ompi)) && { mpi_hosts="-H"; mpi_ppn="-N"; }
mpirun=$(command -v mpirun)
export mpi_hosts mpi_ppn mpirun

if ((!${#SrvIter[*]})); then SrvIter[0]=$ns; fi
if ((!${#ClnIter[*]})); then ClnIter[0]=$nc; fi

unset IFS
srv_opt="$oExtraSrvOpt"
if ((oVERBOSE)); then
    export tVERBOSE=1
    srv_opt="$srv_opt -v 6"
fi
((err=0))
TEST_BIN="${TEST_DIR}/libexec/${oAPP}"
if [ ! -x ${TEST_BIN} ]; then
  TEST_BIN="${TEST_DIR}/bin/${oAPP}"
  if [ ! -x ${TEST_BIN} ]; then
    echo "Test file not found: ${TEST_BIN}"
    exit 1
  fi
fi
SRV_BIN="${TEST_DIR}/bin/unifycrd"
export TEST_BIN SRV_BIN
# Adaptive routing on/off
if ((oAdaptiveRouting)); then
  export FI_ZHPE_QUEUE_TC="0x101"
fi
# FS type?
case "${oFStype^^}" in
  FAM* | 2)    fstype=2 ;;
  UNI* | 1)    fstype=1 ;;
  *)           fstype=0 ;;
esac
ITR=""
if [[ "$oAPP" =~ ior ]]; then
  ((tIOR=1))
  cycles=1
  ITR="-i $oCycles"
else
  ((fstype<1)) && { echo "Wrong fs type:$oFStype"; exit 1; }
  ((cycles = oCycles))
fi
clMPImap=
if ((ompi)); then
  oMPIchEnv="${oMPIchEnv} --bind-to none -x FI_MR_CACHE_MONITOR -x LD_LIBRARY_PATH -x PATH -x MPIROOT"
  oMPIchEnv+=" -x TEST_BIN -x SRV_OPT -x ZHPEQ_HOSTS"
  if ((oTCP)); then
    oMPIchEnv+=" --mca btl ^ofi,openib,vader --mca mtl ^ofi,psm,psm2,portals4 --mca pml ^ucx --mca btl_ofi_disable_sep true --mca mtl_ofi_enable_sep 0"
  else
    oMPIchEnv+=" --mca btl ^openib,tcp,vader --mca mtl ^psm,psm2,portals4 --mca pml ^ucx --mca mtl_ofi_provider_include zhpe --mca mtl_ofi_data_progress manual --mca btl_ofi_provider_include zhpe --mca btl_ofi_progress_mode manual --mca osc_rdma_aggregation_limit 0 --mca opal_leave_pinned 0 --mca opal_leave_pinned_pipeline 0 --mca btl_ofi_disable_sep true --mca mtl_ofi_enable_sep 0"
  fi
  if ((oAdaptiveRouting)); then
    oMPIchEnv+=" -x FI_ZHPE_QUEUE_TC"
  fi
  clMPImap="--map-by :OVERSUBSCRIBE"
fi
if ((mpich)); then
  if ((oTCP)); then
    oMPIchEnv+=" -genv MPIR_CVAR_OFI_USE_PROVIDER=sockets"
  fi
fi
if ((tVERBOSE)); then
  echo -n "MPI favor: "
  ((mpich))&& echo "MPICH"
  ((ompi))&& echo "ompi"
  echo "App: ${TEST_BIN}"
  ((fstype==2)) && echo "FS type: FAMfs" || echo "FS type: $fstype"
fi
cNUMAshell=
if ((oNUMActl)); then
    cNUMAshell="${SCRIPT_DIR}/mpi_numactl.sh"
fi

# Set constants in config file (FAMFS_CONF)
#copy FAMFS config file to current dir
if [ ! -f "$FAMFS_CONF" ]; then
    moniker="${oDATA}D:${oCHUNK}"
    cp -Pf ${SCRIPT_DIR}/famfs.conf.template ${WRK_DIR}/${FAMFS_CONF}
    update_ini "layout" "name" "\"$moniker\""
    update_ini "devices" "extent_size" "${ExtSize}"
    ((oVERBOSE))&& update_ini log verbosity 6
    if ((ns==1)); then
        Servers=`make_list "$hh" 1 "$oNodeSuffix"`
        update_ini ionode host "${Servers[0]}"
    fi
    ((oMultiEP))&& SingleEP="false" || SingleEP="true"
    update_ini devices single_ep $SingleEP
    echo "Layout moniker: $moniker"
fi
echo "configuration file: ${PWD}/${FAMFS_CONF}"

for ((si = 0; si < ${#SrvIter[*]}; si++)); do
    Servers=`make_list "$hh" "${SrvIter[$si]}" "$oNodeSuffix"`
    export Servers
    ns=`count $Servers`
    (($ns==0))&& { echo "Error: zero Servers!"; exit 1; }
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
        Clients=`make_list "$cc" "${ClnIter[$ci]}" "$oNodeSuffix"`
        export Clients
        AllNodes="$Servers,$Clients"
        [ -z "$mdExclusive" ] || AllNodes+=",$mdExclusive"
        all_n=$(add_mynode "$AllNodes") # Force my node included
        echo "=== $Clients -> $Servers [Meta: $mdServers] ===" >> $TEST_LOG
        nc=`count $Clients`

        for ((i = 0; i < ${#RANK[*]}; i++)); do
            export Ranks="${RANK[$i]}"
            if ((ompi)); then
                ((tnc=nc*Ranks))
                cMPImap="${clMPImap} -n $tnc"
            fi
            for ((j = 0; j < ${#TXSZ[*]}; j++)); do
                transfersz=${TXSZ[$j]}
                dsc="[$nc*${RANK[$i]}]->$ns Block=$blksz Segments=$seg"
                dsc="$dsc Writes=$transfersz"
                if [ -z "${RDSZ[$j]}" ]; then
                    dsc="$dsc <no reads>"
                else
                    if ((RDSZ[$j] < 0)); then
                        dsc="$dsc <no reads>"
                    else
                        dsc="$dsc Reads=${RDSZ[$j]}"
                    fi
                fi
                if ((nPatterns>1)); then
                    dsc="$dsc $oTwoPasses"
                fi
                if ((oN2N)); then
                    ((tIOR)) && ptrn="-F" || ptrn="-p 1"
                    dsc="$dsc N-to-N"
                else
                    ((tIOR)) && ptrn="" || ptrn="-p 0"
                    dsc="$dsc N-to-1"
                fi
                wu=""
                if ((wup == 0)); then
                    dsc="$dsc <no warmup>"
                else
                    ((tIOR)) && ITR="-i $((oCycles+1))" || wu="-W $wup"
                    ((tIOR)) || dsc="$dsc WARMUP=$wup"
                fi

                # run Client app one or two times, with specific i/o pattern
                for ((iPattern=0; iPattern<nPatterns; iPattern++)); do

                    ((iPattern==0 && nPatterns>1))&& oSEQ=1 || oSEQ=0

                    if [ -z "${RDSZ[$j]}" ]; then
                        reads=""
                    else
                        if ((RDSZ[$j] < 0)); then
                            reads=""
                        else
                            reads="${RDSZ[$j]}"
                        fi
                    fi
                    if ((nPatterns==1)); then
                        ((tIOR))&& reads="-w -r" || reads="-w ${TXSZ[$j]} -r ${RDSZ[$j]}"
                    elif ((iPattern==0)); then
                        transfersz=${TXSZ[$j]}
                        ((tIOR))&& reads="-w" || reads="-w $transfersz"
                    else
                        transfersz=${RDSZ[$j]}
                        ((tIOR))&& reads="-r" || reads="-r $transfersz"
                    fi

                    vfy=""
                    if ((oVFY)); then
                        dsc="$dsc with VFY"
                        if ((tIOR)); then
                            ((iPattern==0))&& vfy="-G 1234567890" || vfy="-R -G 1234567890"
                        else
                            vfy="-V"
                        fi
                    fi
                    if (($oSEQ)); then
                        ((tIOR)) && seq="" || seq="-S 1"
                        dsc="$dsc SEQ"
                    else
                        ((oVFY)) && ((tIOR)) && { echo "Can't combine verify & random"; exit 1; }
                        ((tIOR)) && seq="-z" || seq="-S 0"
                        dsc="$dsc RANDOM"
                    fi

                    for ((k = 0; k < cycles; k++)); do
                        ((mem = (nc*RANK[i]*seg*blksz + nc*RANK[i]*wup)/ns))
                        ((mem = (mem/1024/1024/1024 + 1)*1024*1024*1024))
                        # TODO: check device size >= $mem

                        BLK="-b $blksz"
                        SEG="-s $seg"
                        WSZ="-t $transfersz"
                        RSZ="$reads"
                        WUP="$wu"
                        PTR="$ptrn"
                        SEQ="$seq"
                        VFY="$vfy"

                        export DSC="$dsc"
                        export AllNodes
                        export all_n
                        export oMPIchEnv
                        export cMPImap
                        export cNUMAshell
                        export SRV_OPT="$srv_opt"
                        export iPattern
                        export nPatterns

                        ((tIOR)) \
                          && opts="-o ${tstFileName} $BLK $SEG $WSZ $RSZ $VFY $PTR $SEQ $ITR -O unifycr=$fstype -a POSIX -g $oExtraOpt" \
                          || opts="-f ${tstFileName} $BLK $SEG $WSZ $RSZ $VFY $PTR $SEQ $WUP -U $fstype -D 0 -u 1 $oExtraOpt"
                        opts=( $(echo $opts) )
                        TEST_OPTS=${opts[*]} # jam whitespaces
                        export TEST_OPTS

                        ((kk = k + 1))
                        if ((iPattern==0)); then
                            echo "Starting cycle $kk of: $DSC"
                        else
                            echo "Starting cycle $kk (2nd) of: $DSC"
                        fi
                        if ${SCRIPT_DIR}/test_cycle.sh; then
                            echo "Finished OK"
                        else
                            ((err++))
                            echo "Finished with ERRORS"
                        fi
                    done
                done
            done
        done
        echo "===" >> $TEST_LOG
    done
done
echo "Error count: $err"
(($err))&& exit 1 || exit 0
