MDHIM - Multi-Dimensional Hashing Indexing Middleware

Description
---------------
This version of MDHIM package is customized to support UnifyCR. 
In order to test these extended interfaces and implementations,
two test files are provided in the directory tests/singletests
(range_bget.c and range_test.c). The test scripts for these two
files are range_bget.sh range_test.sh.

MDHIM is a parallel key/value store framework written in MPI.
Unlike other big data solutions, MDHIM has been designed for an HPC
environment and to take advantage of high speed networks.

Building the Tests
---------------
1. cd tests
2. Type: make
3. If all went well, you have all the tests compiled

mdhimtst (mdhimtst.c)
---------------
Typical setup to run file: ./mdhimtst -ftest.txt -q -t5 -d3 -r0~2 -w1 -p ./

Typical batch file setup:

put single_insert.txt
get single_insertget.txt
del single_insertdel.txt

Batch command file setup:

For put get del bput bget bdel 
[command] [#of items in file(if necessary)] [file containg key and value (if necessary)] 

For nput ngetn (random numbers are generated for this function)
[#number of records to put/get] [key size (only applicapble for byte/strng)]
[value size (nput only)] [size correctance number]

For flush (only command is used to flush)

Parameters:
 -f<BatchInputFileName> (file with batch commands)
 -d<DataBaseType> (Type of DB to use: levelDB=1 mysql=3)
 -t<IndexKeyType> (Type of keys: int=1, longInt=2, float=3, double=4, longDouble=5,
  string=6, byte=7)
 -p<pathForDataBase> (path where DB will be created)
 -n<DataBaseName> (Name of DataBase file or directory)
 -b<DebugLevel> (MLOG_CRIT=1, MLOG_DBG=2)
 -a (DB store append mode. By default records with same key are overwritten.
  This flag turns on the option to append to existing values.
 -w<Rank modlus> This flag turns on the option to either allow or deny threads to
  do command based on if it is dividiable by the modlus of the modulus number
 -r<lowest rank number> ~ <highest rank number>This flag turns on the option to either
  allow or deny threads to do command based on if the rank falls inclusively inbetween
  the rank ranges. NOTE: You must use the '~' inbetween the numbers. Example: -r0~2
 -q<0|1> (Quiet mode, default is verbose) 1=write out to log file



