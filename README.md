# UnifyCR: A Distributed Burst Buffer File System - 0.1.0

Node-local burst buffers are becoming an indispensable hardware resource on
large-scale supercomputers to buffer the bursty I/O from scientific
applications. However, there is a lack of software support for burst buffers to
be efficiently shared by applications within a batch-submitted job and recycled
across different batch jobs. In addition, burst buffers need to cope with a
variety of challenging I/O patterns from data-intensive scientific
applications.

UnifyCR is a user-level burst buffer file system under active development.
UnifyCR supports scalable and efficient aggregation of I/O bandwidth from burst
buffers while having the same life cycle as a batch-submitted job. While UnifyCR
is designed for N-N write/read, UnifyCR compliments its functionality with the
support for N-1 write/read. It efficiently accelerates scientific I/O based on
scalable metadata indexing, co-located I/O delegation, and server-side read
clustering and pipelining.

## Checkout
```
   git clone https://github.hpe.com/pathforward-wp5/FAMfs.git
   cd FAMfs; git submodule init
   git submodule update --recursive --remote
```

Note 1: If behind a firewall you may need to specify the proxy in 'git submodule update' command:
```
   git -c http.proxy=http://web-proxy.corp.hpecorp.net:8080 submodule update --recursive --remote
```

Note 2: Ensure you have "diff.submodule" property set in your git config to "log":
```
   git config --global diff.submodule "log"
```

## Set ENV
Ensure you have installed the dependencies: yasm (or masm), mpich, leveldb, gotcha, libfabric (zhpe-support, zhpe-libfabric and probably zhpe-driver).
For compiling FAMfs please set CPPFLAGS, LDFLAGS, PKG_CONFIG_PATH, LD_LIBRARY_PATH and PATH to corresponding path in your test folder. Then source the additional envioronment variables from 'scripts/setup-env' file in FAMfs folder.
```
   export TEST_DIR=<my_test_dir>
   export CPPFLAGS+=" -I${TEST_DIR}/include"
   export LDFLAGS+=" -L${TEST_DIR}/lib"
   export LD_LIBRARY_PATH="${TEST_DIR}/lib:${LD_LIBRARY_PATH}"
   export PKG_CONFIG_PATH="${TEST_DIR}/lib/pkgconfig:${PKG_CONFIG_PATH}"
   export PATH="${TEST_DIR}/bin:$PATH"
   cd <path_to_FAMfs>; source scripts/setup-env
```

## Configure FAMfs
Configure and build the package:
```
   make distclean; ./autogen.sh && ./configure --prefix=$TEST_DIR --disable-debug --with-gotcha=$TEST_DIR --enable-shared=famfs,libisal && echo Ok
   make clean; make -j install && echo Ok
```

## Tests
Run the regression and unit tests:
```
   make check && echo Ok
   make -C common/src test
   make -C meta/src test
```

## Run Server
Copy FAMFS configuration file (scripts/famfs.conf.example) to /etc or the current directory: famfs.conf
Edit ionodes, devices, device sections in the configuration file upon your needs.
Run FAMS server daemon:
```
   mpirun -hosts 127.0.0.1 -np 1 /bin/bash -c 'unifycrd'
```

## Documentation
Full UnifyCR documentation is contained [here](http://unifycr.readthedocs.io).

Use [Build & I/O Interception](http://unifycr.readthedocs.io/en/latest/build-intercept.html)
for instructions on how to build and install UnifyCR.

## Build Status
The current status of the UnifyCR dev branch is:

[![Build Status](https://api.travis-ci.org/LLNL/UnifyCR.png?branch=dev)](https://travis-ci.org/LLNL/UnifyCR)

## Contribute and Develop
We have a separate document with
[contribution guidelines](./.github/CONTRIBUTING.md).
