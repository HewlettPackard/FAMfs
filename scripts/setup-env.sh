export PATH=/admin/fssw/spack/bin:$PATH
source /admin/fssw/spack/share/spack/setup-env.sh
spack load leveldb
spack load gotcha
export LD_LIBRARY_PATH=/opt/pfsw/fssw/unifycr/lib:$LD_LIBRARY_PATH
export UNIFYCR_EXTERNAL_DATA_DIR=/opt/ramdisk
export UNIFYCR_EXTERNAL_META_DIR=/opt/ramdisk
export UNIFYCR_META_DB_PATH=/opt/ramdisk
export UNIFYCR_CHUNK_MEM=0
export UNIFYCR_META_SERVER_RATIO=1
export UNIFYCR_META_DB_NAME=burstfs_db
export UNIFYCR_SPILLOVER_SIZE=1G
export UNIFYCR_SERVER_DEBUG_LOG=/tmp/unifycr.log
