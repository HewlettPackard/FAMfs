# FAMfs I/O node server and test

## Initialize isa-l folder with this command
git submodule update --init

## How to build
```
   cd node/isa-l
   ./autogen.sh
   ./configure --prefix=/shared/ivanodmi/test4wp5 --enable-debug
   make
   make install
   cd ..
   make
```

## ENV
```
   TEST_DIR=...
   export PKG_CONFIG_PATH="${TEST_DIR}/lib/pkgconfig:${PKG_CONFIG_PATH}"
   export PATH="${TEST_DIR}/bin:${PATH}"
   export LD_LIBRARY_PATH="${TEST_DIR}/node/isa-l/.libs:${LD_LIBRARY_PATH}"
```

