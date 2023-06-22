# Cubicrypt

This project implements a small mechanism for authentication and encryption of
datagrams for secure transmission over untrusted (simplex or duplex) channels.

The protocol is designed to be simple, almost stateless, and reliable and secure
even across system malfunctions that are likely to occur on embedded devices in
space. The library minimizes write operations to persistent storage to reduce
wear and delays and does not require a cryptographically secure source of
randomness for basic operation.

The only required cryptographic primitive is [AES][]. It is used with a 256-bit
primary key to derive 128-bit session keys, which are again used with [AES][] in
[Galois/Counter Mode (GCM)][]. Even on embedded devices, AES-GCM often benefits
from hardware acceleration.

Cubicrypt supports the following implementations of the required cryptographic
primitives:

- [gcrypt][]
- [Mbed TLS][]
- [Nettle][]
- [OpenSSL][] (default)
- [STM32 cryptographic library (CMOX)][]

[AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[Galois/Counter Mode (GCM)]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[Mbed TLS]: https://github.com/ARMmbed/mbedtls
[Nettle]: https://github.com/gnutls/nettle
[OpenSSL]: https://github.com/openssl/openssl
[STM32 cryptographic library (CMOX)]: https://www.st.com/en/embedded-software/x-cube-cryptolib.html
[gcrypt]: https://github.com/gpg/libgcrypt
