# tls-parser

Tested only on GNU/Linux (RHEL 6.8). Might need some minor codechanges on other systems (especially Windows).

Compilation

```
gcc -o tls-parser tls_parser.c tls_parser.h
```

Usage

```
./tls-parser <PATH_TO_TLS_MESSAGE>
```

Examples

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
