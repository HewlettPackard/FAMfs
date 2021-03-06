#!/bin/bash
[ -z "$TEST_DIR" ]&& { echo "Error: TEST_DIR is not set!"; exit 1; }
F_DAEMON_NM="famfsd"
SRC_DIR="${TEST_DIR}/src"
SCRIPT_DIR=${SRC_DIR}/FAMfs/scripts
WRK_DIR=${SCRIPT_DIR}/t
export SCRIPT_DIR F_DAEMON_NM
FAMFS_CONF="famfs.conf"
EDR_COLLECTED_FN="EDR.collected"
# export FAMFS_DO_STATS=1 # Enable if you want stats

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

# parseTwoPasses $optionQ aCNdelta aRECONF aSEQ
function parseTwoPasses() {
  local p token pref val
  let p=0
  while IFS=: read -a token -d,
  do
    case ${#token[@]} in
      1) val=${token[0]}; pref= ;;
      2) pref=${token[0]}; val=${token[1]}; ;;
      *) echo "Syntax error in two_passes option, token >${token[@]}<"; exit 1 ;;
    esac
    # prefixes: CN-=<number> or CONF=<conf_file>
    if [ -z "$pref" ]; then
      eval $"$2"[p]=0
      eval $"$3"[p]=""
    else
      prop=${pref#*=}
      [ -z "$prop" ] && { echo "Syntax error in two_passes option @$p, missing '=*' in prefix >${pref}<"; exit 1; }
      # CN down?
      if [[ "$pref" =~ ^CN-=[0-9]+ ]]; then
        eval $"$2"[p]=$prop
        eval $"$3"[p]=""
      elif [[ "$pref" =~ ^CONF ]]; then
        eval $"$2"[p]=0
        eval $"$3"[p]=$prop
      else
        echo "Syntax error in two_passes option @$p, wrong prefix >${pref}<"
        exit 1
      fi
    fi
    # values: SEQ or RND
    case "$val" in
      [sS] | SEQ) eval $"$4"[p]=1 ;;
      [rR] | RND) eval $"$4"[p]=0 ;;
      *) echo "Syntax error in two_passes option @$p, bad value >${val}<"; exit 1 ;;
    esac
    #if ((tVERBOSE)); then
    #  eval echo "two_passes: pass $((p+1)) - "'CN-=${'${2}'[p]} CONF=${'${3}'[p]} SEQ=${'${4}'[p]}'
    #fi
    ((p++))
  done <<< "$1,"
}

# wait until all EDR files appear: there should be exactly one file per node
function wait_for_edrs() {
  local n=0
  echo "Wait for EDR files"
  while ! pdsh -w "$Servers" -N -S "r=\$(find /tmp -maxdepth 1 -type f -name 'EDR.0-*.*'|wc -l); exit \$((r!=1))" 2>/dev/null; do
    ((n++%10==0))&& echo -n .
    sleep 1
  done
}

# wait for /tmp/EDR.0-*.* files to appear exactly one per IO node
#and set edr_avg edr_min and edr_max vars
function collect_edr_time() {
  local n i=0 sum=0 min=0 max=0 avg=0
  wait_for_edrs
  while read n; do
    ((sum+=n))
    ((min=(min==0?n:(n<min?n:min))))
    ((max=(n>max?n:max)))
    ((i++))
  done < <(pdsh -w "$Servers" -N "echo \$(< /tmp/EDR.0-*.* )")
  ((i>0))&& ((avg=sum/i))
  eval $"$1"_avg=$avg
  eval $"$1"_min=$min
  eval $"$1"_max=$max
  # Append collected datea to EDR.collected file in current dir
  echo "### $dsc" >> $EDR_COLLECTED_FN
  echo "=== avg=$avg min=$min max=$max" >> $EDR_COLLECTED_FN
  pdsh -w "$Servers" "echo \$(< /tmp/EDR.0-*.* )" >> $EDR_COLLECTED_FN
  echo "===" >> $EDR_COLLECTED_FN
}


#
# Working DIR
#
mkdir -p ${WRK_DIR}
cd ${WRK_DIR}

#
# Command line
#

# set default to command line options requires an argument, so make it optional
optline=()
i=1
for t in "$@"; do
    optline+=( "$t" )
    ((i++))
    [[ ! "${!i}" =~ ^[-] ]]&& ((i<=$#))&& continue;
    # insert arguments that should not start with '-'
    case "$t" in
    --) break ;;
    # list of options which have optional arguments
    -W | --warmup) optline+=( "1" ) ;; # warmup default: 1
    -r | --reads) optline+=( "W" ) ;; # read transfer size default: same as writes
    esac
done

# parse the options in $optline with getopt
OPTS=`getopt -o aA:D:I:i:S:C:R:b:s:nNw:r:W:c:vqQ:VE:u:F:M:m:tx:X:O:U -l adaptive,app:,data:,iter-srv:,iter-cln:,servers:,clients:,ranks:,block:,segment:,n2n,numactl,writes:,reads:,warmup:,cycles:,verbose,sequential,two_passes:,verify,extent:,chunk:,fs_type:,mpi:,md:,tcp,suffix:,extra:,srv_extra:,multi_ep -n 'parse-options' -- "${optline[@]}"`
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
tstFileMnt="/tmp/mnt"
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

if [[ "$oREADS" == W ]]; then oREADS=$oWRITES; fi
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

srv_opt="$oExtraSrvOpt"
((tVERBOSE=0))
if ((oVERBOSE)); then
    export tVERBOSE=1
    srv_opt="$srv_opt -v 6"
fi

nPatterns=1
tRECONF=0
if [ ! -z "$oTwoPasses" ]; then
  nPatterns=2
  aCNdelta=()
  aRECONF=()
  aSEQ=()
  # parse option into arrays: CNdelta, RECONF filename, SEQ/RND bit
  parseTwoPasses "$oTwoPasses" aCNdelta aRECONF aSEQ
  # validate configuration file
  for ((i=0;i<nPatterns;i++)); do
    _f=${aRECONF[$i]}
    if [ ! -z "$_f" ]; then
        tRECONF=1
        [ ! -f "$_f" ] && { echo "Configuration file $_f not found!"; exit 1; }
    fi
  done
  if ((tRECONF)); then
    touch "$EDR_COLLECTED_FN" 2>&- || { echo "Bad faile name or path=$EDR_COLLECTED_FN"; exit 1; }
  fi
fi

blksz=$(getval $oBLOCK)
wup=$(getval $oWARMUP)
seg=$(getval $oSEGMENT)
extsz=$(getval $ExtSize)
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

((err=0))
# Server and Client executives
TEST_BIN="${TEST_DIR}/libexec/${oAPP}"
if [ ! -x ${TEST_BIN} ]; then
  TEST_BIN="${TEST_DIR}/bin/${oAPP}"
  if [ ! -x ${TEST_BIN} ]; then
    echo "Test file not found: ${TEST_BIN}"
    exit 1
  fi
fi
SRV_BIN="${TEST_DIR}/bin/${F_DAEMON_NM}"
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
if [[ "$oAPP" =~ ior ]]; then
  ((tIOR=1))
  ((fstype==2)) || { echo "Wrong fs type:$oFStype"; exit 1; }
else
  ((fstype<1)) && { echo "Wrong fs type:$oFStype"; exit 1; }
fi
clMPImap=
if ((ompi)); then
  oMPIchEnv="${oMPIchEnv} --bind-to none -x FI_MR_CACHE_MONITOR -x LD_LIBRARY_PATH -x PATH -x MPIROOT"
  oMPIchEnv+=" -x TEST_BIN -x SRV_OPT -x ZHPEQ_HOSTS -x UNIFYCR_CONFIGFILE -x F_DAEMON_NM"
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
FP_FAMFS_CONF_DEF="${PWD}/${FAMFS_CONF}"
export UNIFYCR_CONFIGFILE=$FP_FAMFS_CONF_DEF
echo "configuration file: $UNIFYCR_CONFIGFILE"

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
        iCln=${ClnIter[$ci]}
        Clients=`make_list "$cc" "$iCln" "$oNodeSuffix"`
        nc=`count $Clients`
        AllNodes="$Servers,$Clients"
        [ -z "$mdExclusive" ] || AllNodes+=",$mdExclusive"
        all_n=$(add_mynode "$AllNodes") # Force my node included
        echo "=== $Clients -> $Servers [Meta: $mdServers] ===" >> $TEST_LOG

        for ((i = 0; i < ${#RANK[*]}; i++)); do
            nRanks="${RANK[$i]}"
            for ((j = 0; j < ${#TXSZ[*]}; j++)); do
                transfersz=${TXSZ[$j]}
                dsc="[${iCln}*${RANK[$i]}]->$ns Block=$blksz Segments=$seg"
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
                ((tVFY=oVFY))&& dsc="$dsc with VFY"
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
                    if ((tIOR)); then
                        ((nPatterns==1))&& { echo "Error: ior has no support for warm-up!"; exit 1; }
                    else
                        wu="-W $wup"
                        dsc="$dsc WARMUP=$wup"
                    fi
                fi

                # run Client app one or two times, with specific i/o pattern
                for ((iPattern=0; iPattern<nPatterns; iPattern++)); do

                    tCln=$iCln
                    if ((nPatterns>1)); then
                        vSEQ=${aSEQ[iPattern]}

                        tCNdelta=${aCNdelta[iPattern]}
                        ((tCln-=tCNdelta))
                        ((tCln<1)) && { echo "Error: Can't run test with ${iCln}-${tCNdelta} compute nodes!"; exit 1; }
                        Clients=`make_list "$cc" "$tCln" "$oNodeSuffix"`
                        ((tCNdelta))&& echo "=== on $tCln client nodes(-${tCNdelta}): $Clients ===" >> $TEST_LOG

                        FP_FAMFS_CONF=${aRECONF[iPattern]}
                        [ -z "$FP_FAMFS_CONF" ]&& FP_FAMFS_CONF=$FP_FAMFS_CONF_DEF
                        # reconfigure server?
                        if [[ "$FP_FAMFS_CONF" != "$UNIFYCR_CONFIGFILE" ]]; then
                            # sleep 30
                            dsc="$dsc RECONF"
                            export UNIFYCR_CONFIGFILE=$FP_FAMFS_CONF
                            if ! iPattern=-1 tStartServer=0 tStopServer=0 ${SCRIPT_DIR}/test_cycle.sh; then
                                echo "Failed to reconfigure Server!"
                                exit 1
                            fi
                            # wait for /tmp/EDR.0-*.* files to appear exactly one per IO node
                            # and set edr_avg edr_min and edr_max vars
                            if ((iPattern==1)); then
                                collect_edr_time edr
                                echo "### Recovery time: min: $edr_min max: $edr_max avg: $edr_avg" >> $TEST_LOG
                            fi
                        fi
                    else
                        vSEQ=$oSEQ
                        Clients=`make_list "$cc" "$tCln" "$oNodeSuffix"`
                    fi

                    ((tnc=nc*nRanks))
                    if ((ompi)); then
                        cMPImap="${clMPImap} -n $tnc"
                    else
                        cMPImap="-np $tnc"
                    fi

                    # test pattern
                    vCycles=$oCycles
                    ioPatternRW=
                    if ((nPatterns==1)); then
                        ((RDSZ[$j]>0)) && ioPatternRW=RW || ioPatternRW=W
                    elif ((iPattern==0)); then
                        vCycles=$((tVFY?2:1))
                        ioPatternRW=W
                    else
                        ioPatternRW=R
                    fi

                    if (($vSEQ)); then
                        ((tIOR)) && seq="" || seq="-S 1"
                        dsc="$dsc SEQ"
                    else
                        ((tIOR)) && seq="-z" || seq="-S 0"
                        dsc="$dsc RANDOM"
                    fi

                    ITR=""
                    if ((tIOR)); then
                        if ((oVFY)); then
                            ((vSEQ==0))&& { echo "Can't combine verify & random"; exit 1; }
                            ITR="-i 1"
                        else
                            cycles=$oCycles
                            if ((nPatterns>1)) && [[ $ioPatternRW == W ]]; then
                                cycles=$((oWARMUP?2:1))
                            fi
                            ITR="-i $cycles"
                            vCycles=1
                        fi
                    fi

                    ((tVFY && tIOR==0))&& vfy="-V" || vfy=""

                    for ((k = 0; k < vCycles; k++)); do
                        ((mem = (nc*RANK[i]*seg*blksz + nc*RANK[i]*wup)/ns))
                        ((mem = (mem/1024/1024/1024 + 1)*1024*1024*1024))
                        # TODO: check device size >= $mem

                        # set i/o pattern
                        case $ioPatternRW in
                        RW) if ((tIOR)); then
                                reads="-w -r"
                                ((tVFY))&& vfy="-R -G 1234567890"
                            else
                                reads="-w ${TXSZ[$j]} -r ${RDSZ[$j]}"
                            fi
                            ;;
                        W ) transfersz=${TXSZ[$j]}
                            if ((tIOR)); then
                                reads="-w"
                                ((tVFY))&& vfy="-G 1234567890"
                            else
                                reads="-w $transfersz"
                            fi
                            ;;
                        R ) transfersz=${RDSZ[$j]}
                            if ((tIOR)); then
                                reads="-r"
                                ((tVFY))&& vfy="-R -G 1234567890"
                            else
                                reads="-r $transfersz"
                            fi
                            ;;
                        *) break ;;
                        esac

                        BLK="-b $blksz"
                        SEG="-s $seg"
                        WSZ="-t $transfersz"
                        RSZ="$reads"
                        WUP="$wu"
                        PTR="$ptrn"
                        SEQ="$seq"
                        VFY="$vfy"

                        export DSC="$dsc"
                        export Clients
                        export AllNodes
                        export all_n
                        export Servers
                        export oMPIchEnv
                        export cMPImap
                        export cNUMAshell
                        export SRV_OPT="$srv_opt"
                        export iPattern
                        export nPatterns
                        export tStartServer=$((iPattern==0 && k==0))
                        export tStopServer=$((iPattern==nPatterns-1 && k==vCycles-1))

                        ((tIOR)) \
                          && opts="-o ${tstFileName} $BLK $SEG $WSZ $RSZ $VFY $PTR $SEQ $ITR -a POSIX --posix.famfs --posix.mountpoint $tstFileMnt -g $oExtraOpt" \
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

                        # hack: amend ioPatternRW for read w/verify pass just after write
                        if ((tVFY && nPatterns>1 && iPattern==0))&& [[ $ioPatternRW == W ]]; then
                            ioPatternRW=R
                            echo "### verify data after write" >> $TEST_LOG
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
