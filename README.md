# FAMfs: A Gen-Z based distributed fabric attached memory (FAM) filesystem

FAMfs s a Gen-Z based distributed fabric attached memory (FAM) filesystem
which is optimized for HPC applications using checkpoint/restart as a mechanism
to tolerate cluster components failures.

The FAMfs primary design goal is to achieve a write performance that saturates
the underlying FAM media. This is done by eliminating contention between the writer
processes and therefore removes the need for locking. FAMfs uses Remote Memory
Access (RMA) techniques to achieve maximum performance through explicit one-sided
communication via the Gen-Z bridge data mover. Data encoding is performed on
the IO-nodes asynchronously to the user I/O operations. FAMfs also optimizes
read I/O for all checkpoint patterns including the multi-dimensional analysis,
with an aim for a near-linear scalability of the performance with the size
of the cluster. The file system supports multiple IO-nodes that coordinate
the metadata processing of a single namespace file system.

While the initial proof of concept prototype was largely based on LLNL’s UnifyCR,
the current version of FAMfs has been completely rewritten, with the exception
of the MDHIM (multi-dimensional hashing indexing framework) metadata store.
Please see the list of novel and innovative innovative features and algorithms
implemented in FAMfs:
```
• Dynamic topology aware space allocation. Implemented through IO-node based
allocators and compute node based allocator helpers. All metadata maps are
partitioned by IO-node and implemented as dynamic URCU Judy arrays (high
performance associative array).
```
```
• Shared memory based Judy arrays implemented to share metadata maps between
processes within compute nodes in one writer - many readers mode.
```
```
• Libfabric atomics based cluster wide FAM extent maps implemented as bitmap
arrays to support space allocation across all FAM modules without the need
for cluster-wide locks.
```
```
• Multiple filesystems layouts with different geometries and protection levels.
Because FAMfs supports multiple layouts, it is possible to fine tune performance
of applications using different I/O patterns (or different I/O streams within
one application) inside a single filesystem using the same pool of FAM modules.
```
```
• Compute processes (filesystem clients) communicate with allocation helpers
via shared memory based lockless ring queues.
```
```
• Dynamic erasure codes encoding in parallel with I/O. Because data is stored
as log structured segments and never overwritten, there is no danger of a RAID
‘write hole’. FAMfs Encode-Decode-Recovery (EDR) subsystem employs the Intel-developed
ISA-L library to encode data via Reed-Solomon erasure coding and is optimized
for speed and efficiency.
```
```
• Data recovery could be performed in parallel with writing new checkpoints.
Both encoding and recovery processes share the same EDR framework and are
performed on IO-nodes with user configurable priorities. Data verification
has not yet been implemented but could easily be added to the existing EDR framework.
```
## Install dependencies
```
   git clone https://github.com/google/leveldb.git
   cd leveldb && git checkout -b ver_1.20 a53934a3ae1244679 && make
   cp -R include/leveldb ${TEST_DIR}/include/leveldb
   cp out-shared/libleveldb.so.1.20 ${TEST_DIR}/lib
   cp out-static/libleveldb.a ${TEST_DIR}/lib
   cd ..

   git clone https://github.com/LLNL/GOTCHA.git gotcha
   cd gotcha && git checkout tags/0.0.2 -b tag_0.0.2
   ( cd ${TEST_DIR}; ln -s lib lib64 )
   mkdir -p build && cd build && cmake -DCMAKE_INSTALL_PREFIX=/shared/divanov/test_di .. && make install && echo Ok
   cd ../..

   dnf install yasm
   dnf install perl-Test-Harness
```
## Checkout FAMfs
```
   git clone https://github.com/HewlettPackard/FAMfs.git
   cd FAMfs; git submodule init
   git submodule update --recursive --remote
```

Note1: Ensure you have "diff.submodule" property set in your git config to "log":
```
   git config --global diff.submodule "log"
```

Note2: Apply patches from patches folder to URCU and IOR packages:
```
   cd userspace-rcu
   patch -p1 < ../patches/userspace-rcu.PIC
   patch -p1 < ../patches/userspace-rcu.stack_corruption_snapshot_n
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
   cd <path_to_FAMfs>
```

## Configure FAMfs
Configure and build the package:
```
   make distclean; ./autogen.sh && ./configure --prefix=$TEST_DIR --disable-debug --with-gotcha=$TEST_DIR && echo Ok
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
   mpirun -hosts 127.0.0.1 -np 1 /bin/bash -c 'famfsd'
```
