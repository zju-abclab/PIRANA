# PIRANA: Faster Multi-query PIR via Constant-weight Codes

PIRANA is a research library and should not be used in production systems. 
This repository contains the implementation of both single-query PIR and multi-query PIR proposed in the [paper](https://eprint.iacr.org/2022/1401).

## Dependencies
- Microsoft SEAL (version>=4.0.0)
- Microsoft Kuku (version=2.1.0)

[Microsoft SEAL](https://github.com/microsoft/SEAL) and [Microsoft Kuku](https://github.com/microsoft/Kuku) can be installed using the instructions outlined in the repository.

## Building the project
The project can be built using the following command.
```
mkdir build && cd build
cmake ..
make
```
If SEAL or KUKU is not in your path or installed locally, you can try to add `-CMAKE_INSTALL_PREFIX=[PATH TO SEAL/KUKU]`in the commond.

## Parameters
|     Option     |               | Description          |Default|
|:----------------:|:---------------:|:---------------------:|:-------:|
| --num_payload   |       -n      | Number of payloads in database           |16384|
| --payload_size  |  -x |  Byte size of each payload \|pl\|.                   | 256|
| --is_batch    |  -b  | Batch-query PIR or single-query PIR.     |0 (single-query PIR)|
| --num_query   |  -l  | Number of queries.                      |1|
| --is_compress &nbsp;&nbsp;&nbsp;&nbsp;|  -c &nbsp; | Select parameters optimized for communication or computation.  Available only in batch-query PIR.     |0 (Computation friendly)|


## Example
For single-query PIR
```
../bin/pirexamples -b 0 -n 16384 -x 256
```
For multi-query PIR

Computation friendly:
```
../bin/pirexamples -b 1 -l 256 -n 16384 -x 256 -c 0
```

Communication friendly:
```
../bin/pirexamples -b 1 -l 256 -n 16384 -x 256 -c 1 
```
