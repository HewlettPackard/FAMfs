#!/bin/sh

echo
echo ... UnifyCR autogen ...
echo

## Check all dependencies are present
MISSING=""
SUGGEST="Please install them and try again."

# Check for aclocal
env aclocal --version > /dev/null 2>&1
if [ $? -eq 0 ]; then
  ACLOCAL=aclocal
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

# Check for yasm
env yasm --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
  MISSING="$MISSING yasm"
fi

## If dependencies are missing, warn the user and abort
if [ "x$MISSING" != "x" ]; then
  echo "Aborting."
  echo
  echo "The following build tools are missing:"
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

## Do the autogeneration
echo Running ${ACLOCAL}...
$ACLOCAL
echo Running ${AUTOHEADER}...
$AUTOHEADER
echo Running ${TOOL}...
$TOOL --automake --copy --force
echo Running ${AUTOCONF}...
$AUTOCONF
echo Running ${AUTOMAKE}...
$AUTOMAKE --add-missing --force-missing --copy --foreign || exit 1

# Instruct user on next steps
echo
echo "Please proceed with configuring, compiling, and installing."
