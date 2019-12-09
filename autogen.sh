#!/bin/bash

echo
echo ... UnifyCR autogen ...
echo

## Check all dependencies are present
MISSING=""
SUGGEST="Please install them and try again."

# Check for aclocal
env aclocal --version > /dev/null 2>&1
if [ $? -eq 0 ]; then
  loc_acl=$(env aclocal --print-ac-dir)
  gl_acl=$(env - aclocal --print-ac-dir)
  ACLOCAL=aclocal
  if [[ "$loc_acl" != "$gl_acl" ]]; then
    echo "Will run aclocal with third-party M4 files in $loc_acl"
    ACLOCAL="aclocal -I $loc_acl -I $gl_acl"
  fi
else
  MISSING="$MISSING aclocal"
fi

# Check for autoconf
env autoconf --version > /dev/null 2>&1
if [ $? -eq 0 ]; then
  AUTOCONF=autoconf
else
  MISSING="$MISSING autoconf"
fi

# Check for autoheader
env autoheader --version > /dev/null 2>&1
if [ $? -eq 0 ]; then
  AUTOHEADER=autoheader
else
  MISSING="$MISSING autoheader"
fi

# Check for automake
env automake --version > /dev/null 2>&1
if [ $? -eq 0 ]; then
  AUTOMAKE=automake
else
  MISSING="$MISSING automake"
fi

# Check for libtoolize or glibtoolize
env libtoolize --version > /dev/null 2>&1
if [ $? -eq 0 ]; then
  # libtoolize was found, so use it
  TOOL=libtoolize
else
  # libtoolize wasn't found, so check for glibtoolize
  env glibtoolize --version > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    TOOL=glibtoolize
  else
    MISSING="$MISSING libtoolize/glibtoolize"
  fi
fi
if [[ ! -z "$TOOL" ]]; then
  loc_lt=$(env libtool --config|grep 'macro_version=')
  gl_lt=$(env - libtool --config|grep 'macro_version=')
  if [[ "$loc_lt" != "$gl_lt" ]]; then
    if [[ "$loc_acl" == "$gl_acl" ]]; then
      echo "Please re-install aclocal (automake) for third-party M4 files of $loc_lt"
      # libtool is not usable
      MISSING="$MISSING libtool"
    fi
  fi
fi

# Check for tar
env tar -cf /dev/null /dev/null > /dev/null 2>&1
if [ $? -ne 0 ]; then
  MISSING="$MISSING tar"
fi

# Check for ISA-L
ISAL_DIR=node/isa-l
if [ ! -f ${ISAL_DIR}/configure.ac ]; then
  MISSING="$MISSING isa-l"
  SUGGEST="$SUGGEST\n (try to run 'git submodule update --init')"
fi

# Check for URCU
URCU_DIR=userspace-rcu
if [ ! -f ${URCU_DIR}/configure.ac ]; then
  MISSING="$MISSING URCU"
  SUGGEST="$SUGGEST\n (try to run 'cd FAMfs; git submodule update --init --recursive --remote')"
fi

# Check for yasm
env yasm --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
  MISSING="$MISSING yasm"
fi

## If dependencies are missing, warn the user and abort
if [ "x$MISSING" != "x" ]; then
  echo "Aborting."
  echo
  echo "The following build tools are missing or not usable:"
  echo
  for pkg in $MISSING; do
    echo "  * $pkg"
  done
  echo
  echo "${SUGGEST}"
  echo
  exit 1
fi

echo Running autoreconf for $ISAL_DIR
autoreconf --install --symlink -f $ISAL_DIR || { echo "FAILED to auto-configure ISA-L package!"; exit 1; }

echo
echo Running autoreconf for $URCU_DIR
autoreconf --install --symlink -f $URCU_DIR || { echo "FAILED to auto-configure URCU package!"; exit 1; }
echo

## Do the autogeneration
echo Running ${ACLOCAL}...
$ACLOCAL
echo Running ${AUTOHEADER}...
$AUTOHEADER
echo Running ${TOOL}...
$TOOL --automake --copy --force || exit 1
echo Running ${AUTOCONF}...
$AUTOCONF || exit 1
echo Running ${AUTOMAKE}...
$AUTOMAKE --add-missing --force-missing --copy --foreign || exit 1

# Instruct user on next steps
echo
echo "Please proceed with configuring, compiling, and installing."
