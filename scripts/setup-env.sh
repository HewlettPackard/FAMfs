# source /admin/fssw/spack/share/spack/setup-env.sh
WRK_DIR=/dev/shm
# INSTALL_DIR=/ibnfs/${USER}/install/FAMfs
INSTALL_DIR=$(pkg-config --variable=prefix unifycr)

export PATH="${INSTALL_DIR}/bin:${PATH}"
export LD_LIBRARY_PATH="${INSTALL_DIR}/lib:$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="${INSTALL_DIR}/lib/pkgconfig:${PKG_CONFIG_PATH}"

export UNIFYCR_SPILLOVER_SIZE=1G
export UNIFYCR_CHUNK_MEM=0
export UNIFYCR_META_SERVER_RATIO=1
export UNIFYCR_META_DB_NAME=burstfs_db
export UNIFYCR_META_DB_PATH=$WRK_DIR
export UNIFYCR_EXTERNAL_DATA_DIR=$WRK_DIR
export UNIFYCR_EXTERNAL_META_DIR=$WRK_DIR
export UNIFYCR_SERVER_DEBUG_LOG=${WRK_DIR}/unifycr.log
