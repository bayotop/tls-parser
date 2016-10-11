# tls-parser [![Build Status](https://travis-ci.org/bayotop/tls-parser.svg?branch=master)](https://travis-ci.org/bayotop/tls-parser)

Tested only on GNU/Linux (RHEL 6.8). Might need some minor codechanges on other systems (especially Windows).

Compilation

```
gcc -o tls-parser tls_parser.*
```

Usage

```
./tls-parser <PATH_TO_TLS_MESSAGE>
```

Examples

```
$ ./tls-parser src/ClientHello
Identified the following TLS message:

TLS Version: 1.0
Protocol type: 22
Fragment length: 187
Handshake message type: 1

Details of ClientHello:

TLS Version: 1.2
Timestamp: Sat Aug  6 23:54:29 2095
Random data: 4e8d6c934354f96a0fd5ae6546dac586aa86d51baf26ded5f9ab029
SessionID: N/A
Choosen cipher suites:
0xc02b 0xc02f 0xc02c 0xc030 0xcca9 0xcca8 0xcc14 0xcc13 0xc09 0xc013 0xc0a 0xc014 0x09c 0x09d 0x02f 0x035 0x0a
Compresion method: 0
Has extensions: true
Raw extensions data:

06cff1010000100e00b73736c6c6162732e636f6d01700023000d0120106163515341432123050510000012000100e0c268328687474702f312e317550000b02100a080601d017018

Succesfully finished parsing of message!
```

```
$ ./tls-parser ServerHello_InvalidVersion
Identified the following TLS message:

TLS Version: 1.2
Protocol type: 22
Fragment length: 81
Handshake message type: 2

[ERROR]: The message is not of a supported version (TLS 1.0 - TLS 1.2).
```

```
$ ./tls-parser Certificate
Identified the following TLS message:

TLS Version: 1.2
Protocol type: 22
Fragment length: 2905
Handshake message type: 11
Handshake message length: 2901

The certificate chain provided is 2901 bytes long.

Succesfully finished parsing of message!
```
```
$ ./tls-parser ServerHelloDone
Identified the following TLS message:

TLS Version: 1.2
Protocol type: 22
Fragment length: 4
Handshake message type: 14
Handshake message length: 0

Succesfully finished parsing of message!
```
