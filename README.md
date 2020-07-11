# TCP Socket lib

This is a simple lib to interact with TCP sockets in Linux/POSIX systems. It also has an extense openSSL-based API to handle security (hash, HMAC, cypher, EC asymmetric keys, etc).

In the [apps](./apps) folder there is an example how to use it. The example is an heartbeat application, first you need to setup the keys with keyManager, then use heartbeat app to send/receive heartbeats.

## Implementation & Usage

File [src/sslUtility.c](./src/sslUtility.c) has the security features implementation using openSSL C API (make sure you have openSSL library installed before compiling). File [src/tcpSocketLib.c](./src/tcpSocketLib.c) implements the TCP sockets/connections API. Include the header [include/tcpSocketLib.h](./include/tcpSocketLib.h) in your project to use this library.

## Dependencies

This library was tested in Ubuntu 18.04, besides openssl it requires the dependencies in [deps](./deps) to be compiled, they handle threading and command line input.
