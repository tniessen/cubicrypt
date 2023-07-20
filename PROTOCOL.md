# Cubicrypt protocol

This document describes the Cubicrypt protocol.

## Core protocol

The core Cubicrypt protocol is a low-level mechanism that can securely transmit
up to 2<sup>64</sup> data frames using a single pre-shared key, or up to
2<sup>96</sup> frames for applications that utilize epochs. The core protocol
can be used over simplex channels as it does not require any bidirectional
interaction between sender and receiver.

By convention, both in cryptographic protocols and network protocols, all
integers are unsigned and encoded in network byte order (big-endian) and with
fixed width. For example, a 32-bit integer field with value `1234` is encoded
as the octet sequence `00 00 04 d2`.

### Parameters

Each context is parameterized by a 256-bit primary key, a 64-bit context ID, and
a 32-bit epoch. Within a context, up to 2<sup>32</sup> sessions can be
instantiated. Each session within a context has a unique session key that is
used to encrypt and authenticate data that is transmitted during the session.
During a single session, up to 2<sup>32</sup> frames can be transmitted. Once a
session's capacity is exhausted, the sending side automatically creates a new
session.

The sequences of session keys that are produced by two contexts whose parameters
only differ in the epoch field are independent. Therefore, applications may
extend the life span of a pre-shared key by replacing an existing context with a
new context such that the primary key and the context ID remain the same but
such that the epoch of the new context is greater than that of the previous
context. However, the application must implement a mechanism for notifying the
other endpoint of the parameter change, otherwise, the receiving side will be
unable to decode messages after a parameter change has occurred.

Thus, for any given primary key and context ID, a total of up to 2<sup>64</sup>
sessions can be instantiated by applications that utilize the epoch field as
described above.

The context ID may be used to distinguish between a small number of contexts
that use the same primary key. For example, both directions of a duplex channel
may use the same primary key as long as the respective context IDs are
different. However, unlike the epoch field, the context ID must not be used to
extend the life span of a primary key.

Different primary keys must be generated independently. No primary key may be
derived from another primary key. Each primary key should be generated from a
safe amount of entropy.

### Sessions

Each data frame belongs to a session. Sessions are identified by a 32-bit
session identifier. Cubicrypt derives a unique session key for each session.

Each frame within a session is identified by a 32-bit frame identifier, which
limits the number of frames per session to 2<sup>32</sup>. However, the sending
side may decide to start a new session at any point, regardless of the remaining
capacity of the current session.

Cubicrypt goes to great lengths to maximize reliability. Nevertheless,
malfunctions of the receiving system, such as system crashes, may cause the
receiver to be unable to verify the authenticity of frames that belong to
sessions that were being used prior to the malfunction. Therefore, applications
may want to eagerly start new sessions either at regular intervals or when
communication attempts have failed for a certain amount of time.

Cubicrypt writes to persistent storage whenever the session identifier changes.
Applications may want to consider this when deciding when to eagerly start new
sessions.

> **Note**
> The session identifier 0 is reserved. The first session identifier used by a
> new Cubicrypt context is 1.

### Frames

Frames are identified by a pair of 32-bit integers `(S, F)`, where `S` is the
session identifier and `F` is the frame counter. Applications may restrict `S`
and/or `F` to fewer than 32 bits, but to no less than 16 bits and 8 bits,
respectively.

The session identifier `S` is used to derive the session key `K'` (see
[Session key derivation][]), whereas the frame counter `F` is used to construct
the nonce (see [IV construction][]).

The following requirement is crucial for the prevention of replay attacks, and
is enforced by Cubicrypt automatically:

When a frame with the identifier `(S, F)` has been received and has not been
rejected by the decoding routine, all frames that are subsequently received
must be rejected unless their frame identifier `(S', F')` fulfills the following
condition: Either `S'` is strictly greater than `S`, or `S'` is equal to `S` and
`F'` is strictly greater than `F`.

> **Note**
> Cubicrypt supports out-of-order decoding, which relaxes the above requirement.
> Out-of-order decoding does not negatively affect security, but it can still be
> disabled at compile time if desired.

### Additional Authenticated Data (AAD)

Additional data may be associated with each frame that is not considered to be
part of the frame's body and thus, by default, not subject to authentication or
encryption. For example, routing information may be associated with a frame but
may be transmitted in the clear to allow routing decisions without decrypting
the frame's body.

Such data may explicitly be passed as additional authenticated data (AAD), which
causes it to be included in the authentication mechanism. In the above example,
this would prevent an attacker from modifying routing information associated
with a frame.

> **Note**
> Additional authenticated data does not affect the size of the encoded frame,
> but large amounts of additional authenticated data may negatively impact
> performance.

### Session key derivation

Let `K` be the 256-bit primary key. Let `X` be the 64-bit context identifier.
Let `E` be the 32-bit epoch. Let `S` be the 32-bit session identifier.
Let `K'` be the result of the 256-bit AES block cipher when applied to the key
`K` and the 128-bit block that is the concatenation of `X`, `E`, and `S`.
Return `K'`.

```
plaintext := context_id || epoch || session_id
session_key := AES-256-Cipher(primary_key, plaintext)
```

In other words, the AES block cipher is applied to the following 128-bit block
of plaintext:

```
| Application parameters (96 bits)       | Cubicrypt session state (32 bits) |
|----------------------------------------|-----------------------------------|
| Context id (64 bits) | Epoch (32 bits) | Session identifier (32 bits)      |
```

Session keys derived from the same primary key do not collide unless the
application incorrectly constructs more than one context with the same context
id and epoch. Changing the context id or the epoch leads to an independent
sequence of session keys. Only a small number of different context identifiers
may be used with the same primary key.

### IV construction

We use the deterministic construction from Section 8.2.1 of [NIST SP 800-38D][]
with the lengths and positions suggested therein. The leftmost 32 bits of the IV
hold the fixed field, whose value is set to `0`<sup>`32`</sup>. The remaining 64
bits hold the invocation field. The leftmost 32 bits of the invocation field
hold the frame flags. The remaining 32 bits of the invocation field hold the
frame identifier `F`.

```
| Fixed field (32 bits) | Invocation field (64 bits)                          |
|-----------------------|-----------------------------------------------------|
| Reserved (32 bits)    | Flags (32 bits)        | Frame identifier (32 bits) |
|                       | Auth-Only | Reserved   |                            |
|-----------------------|-----------|------------|----------------------------|
| 0000...0000           | A (1 bit) | 000...0000 | F (32 bits)                |
```

### Authenticated encryption

Frames that are subject to encryption are encrypted and authenticated using
AES-GCM. The ciphertext and the authentication tag are obtained by applying
AES-GCM to the computed session key (see [Session key derivation][]), the
computed IV (see [IV construction][]), the given AAD (see
[Additional Authenticated Data (AAD)][]), and the given message.

```
frame_flags := 0
nonce := frame_flags || frame_counter
(ciphertext, auth_tag) := AES-GCM(session_key, nonce, aad, message)
```

### Authentication-only construction

For frames that are not encrypted but only authenticated, AES-GCM is used in its
GMAC variant (see Section 3 of [NIST SP 800-38D][]). This requires to construct
GMAC inputs from the frame's AAD and its body.

```
frame_flags := 0x80000000
nonce := frame_flags || frame_counter
padding := 0 * ((16 - (len(aad) % 16)) % 16)
input := len(aad) || aad || padding || message
auth_tag := AES-GMAC(session_key, nonce, input)
```

The input consists of three parts, which are concatenated:

1. The first 128-bit block of the input encodes the size of the AAD (in bytes)
   as an unsigned 128-bit integer.
2. The next `ceil(len(AAD) / 16)` blocks contain the AAD, padded with trailing
   zeros such that the padded AAD ends at a block boundary. If the length of the
   AAD is a multiple of 128 bits, no padding is added. If the AAD is empty, this
   part is empty.
3. The frame's body itself is the last part. No padding is added.

For example, if the AAD is empty, the GMAC input consists of the 128-bit block
that is all zeros followed by the frame's body.

If both the AAD and the body are empty, the GMAC input consists only of the
128-bit block that is all zeros.

If the AAD consists of 331 bytes, then the GMAC input consists of the 16 bytes
`00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 4b`, the AAD itself, the 5 padding
bytes `00 00 00 00 00`, and the frame's body.

> **Note**
> While the same session key is used for all frames within a session, regardless
> of whether the respective frames are encrypted or merely authenticated, the
> [IV construction][] described above results in different nonces being used
> depending on whether a frame is encrypted or not.

## Key exchange extension

Cubicrypt's optional key exchange extension allows applications to generate new
primary keys that can be used with the core protocol. By correctly utilizing
this mechanism, applications can overcome the finite life span of Cubicrypt
contexts.

Cubicrypt uses a standard construction based on X25519 and SHA-256 for key
exchanges:

```
shared_secret := X25519(own_private_key, peer_public_key)
primary_key := SHA-256(shared_secret)
```

At least one of the X25519 key pairs must be ephemeral. The private key of the
ephemeral key pair is generated randomly and has an entropy of 251 bits, which
leads to sufficient entropy of the derived primary key.

[Additional Authenticated Data (AAD)]: #additional-authenticated-data-aad
[IV construction]: #iv-construction
[NIST SP 800-38D]: https://csrc.nist.gov/publications/detail/sp/800-38d/final
[Session key derivation]: #session-key-derivation
