#include "common.h"

#include <string.h>

#ifndef CUBICRYPT_NO_KEY_EXCHANGE
// Statically generated test vector.
static const uint8_t sat_private_key[CUBICRYPT_KX_PRIVATE_KEY_BYTES] = {
  0x10, 0xea, 0x81, 0x13, 0x27, 0xfe, 0x17, 0x15, 0x8b, 0x7f, 0x4d,
  0x59, 0x74, 0xb0, 0x29, 0x4c, 0xcf, 0x3b, 0x61, 0xbc, 0xd9, 0x68,
  0x70, 0x07, 0x8f, 0x3f, 0x24, 0x0c, 0x6a, 0x89, 0x19, 0x47
};
static const uint8_t sat_public_key[CUBICRYPT_KX_PUBLIC_KEY_BYTES] = {
  0x89, 0x4e, 0x75, 0xdc, 0xb8, 0x8d, 0x3c, 0x95, 0x51, 0xb5, 0x98,
  0xcd, 0x32, 0xb9, 0x25, 0xca, 0xa2, 0x1d, 0x7d, 0xa3, 0x53, 0x68,
  0xbc, 0xd3, 0xf6, 0x04, 0xa3, 0xd6, 0x87, 0x54, 0x35, 0x20
};
static const uint8_t gnd_private_key[CUBICRYPT_KX_PRIVATE_KEY_BYTES] = {
  0xf0, 0xbc, 0xe1, 0x0f, 0xe1, 0x5b, 0x19, 0x35, 0x5a, 0xd2, 0x37,
  0xa7, 0x82, 0xc4, 0xe9, 0xe6, 0xa1, 0x13, 0x52, 0x13, 0x28, 0x1e,
  0xf9, 0x59, 0x95, 0xd9, 0xca, 0x34, 0x75, 0x6f, 0xd9, 0x7c
};
static const uint8_t gnd_public_key[CUBICRYPT_KX_PUBLIC_KEY_BYTES] = {
  0x88, 0xdc, 0x4d, 0x88, 0x64, 0x24, 0xa8, 0xa8, 0x18, 0xc6, 0xe3,
  0xd6, 0x9f, 0x21, 0x41, 0xc5, 0x20, 0xb7, 0xb7, 0x67, 0x76, 0x84,
  0xf4, 0x45, 0x18, 0x63, 0xe6, 0x1b, 0xca, 0xb4, 0x91, 0x7b
};
static const uint8_t expected_primary_key[CUBICRYPT_PRIMARY_KEY_BYTES] = {
  0x05, 0x30, 0xef, 0x2b, 0x39, 0x18, 0x3b, 0xb4, 0xc6, 0x27, 0x40,
  0x1f, 0x57, 0x17, 0x7c, 0xb2, 0x19, 0xc3, 0xf9, 0x88, 0xb9, 0x8d,
  0x58, 0xf4, 0x91, 0x81, 0x07, 0x33, 0xd6, 0xab, 0x0d, 0x77
};

// Helpers for naively validating public and private keys.
static const uint8_t x25519_prime_big_endian[32] = {
  0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
};

static inline bool is_valid_private_key(const uint8_t* key) {
  // Private keys must be clamped correctly.
  return (key[0] & 248u) == key[0] && (key[31] & 192u) == 64u;
}

static inline bool is_valid_public_key(const uint8_t* key) {
  // Public keys must be smaller than 2^255-19. Note that X25519 uses little
  // endian encoding, so we need to compare the bytes in reverse order.
  for (size_t i = 0; i < 32; i++) {
    uint8_t a = key[31 - i];
    uint8_t b = x25519_prime_big_endian[i];
    if (a != b) return a < b;
  }
  return false;
}
#endif

CUBICRYPT_TEST_MAIN(key_exchange) {
#ifndef CUBICRYPT_NO_KEY_EXCHANGE

  // Generate one key pair.
  uint8_t a_public_key[CUBICRYPT_KX_PUBLIC_KEY_BYTES];
  uint8_t a_private_key[CUBICRYPT_KX_PRIVATE_KEY_BYTES];
  assert(cubicrypt_kx_generate_keypair(a_public_key, a_private_key));
  assert(is_valid_private_key(a_private_key));
  assert(is_valid_public_key(a_public_key));

  // Generate another key pair.
  uint8_t b_public_key[CUBICRYPT_KX_PUBLIC_KEY_BYTES];
  uint8_t b_private_key[CUBICRYPT_KX_PRIVATE_KEY_BYTES];
  assert(cubicrypt_kx_generate_keypair(b_public_key, b_private_key));
  assert(is_valid_private_key(b_private_key));
  assert(is_valid_public_key(b_public_key));

  // The generated key pairs should be different.
  assert(memcmp(a_public_key, b_public_key, CUBICRYPT_KX_PUBLIC_KEY_BYTES) !=
         0);
  assert(memcmp(a_private_key, b_private_key, CUBICRYPT_KX_PRIVATE_KEY_BYTES) !=
         0);

  // Derive a new primary key from the two key pairs.
  uint8_t a_primary_key[CUBICRYPT_PRIMARY_KEY_BYTES];
  assert(cubicrypt_kx_derive_primary_key(a_primary_key, b_public_key,
                                         a_public_key, a_private_key));

  // Again, but from the side of the other endpoint.
  uint8_t b_primary_key[CUBICRYPT_PRIMARY_KEY_BYTES];
  assert(cubicrypt_kx_derive_primary_key(b_primary_key, a_public_key,
                                         b_public_key, b_private_key));

  // The generated primary keys should be the same.
  assert_eq(memcmp(a_primary_key, b_primary_key, CUBICRYPT_PRIMARY_KEY_BYTES),
            0);

  // Use an ephemeral key pair with the first (static) key pair.
  uint8_t some_primary_key_a[CUBICRYPT_PRIMARY_KEY_BYTES];
  uint8_t ephemeral_public_key_for_a[CUBICRYPT_KX_PUBLIC_KEY_BYTES];
  assert(cubicrypt_kx_generate_primary_key(some_primary_key_a, a_public_key,
                                           ephemeral_public_key_for_a));
  assert(is_valid_public_key(ephemeral_public_key_for_a));
  // The same key should be derived by A.
  assert(cubicrypt_kx_derive_primary_key(
      a_primary_key, ephemeral_public_key_for_a, a_public_key, a_private_key));
  assert_eq(
      memcmp(a_primary_key, some_primary_key_a, CUBICRYPT_PRIMARY_KEY_BYTES),
      0);

  // Repeat the same process with the second (static) key pair.
  uint8_t some_primary_key_b[CUBICRYPT_PRIMARY_KEY_BYTES];
  uint8_t ephemeral_public_key_for_b[CUBICRYPT_KX_PUBLIC_KEY_BYTES];
  assert(cubicrypt_kx_generate_primary_key(some_primary_key_b, b_public_key,
                                           ephemeral_public_key_for_b));
  assert(is_valid_public_key(ephemeral_public_key_for_b));
  // The same key should be derived by B.
  assert(cubicrypt_kx_derive_primary_key(
      b_primary_key, ephemeral_public_key_for_b, b_public_key, b_private_key));
  assert_eq(
      memcmp(b_primary_key, some_primary_key_b, CUBICRYPT_PRIMARY_KEY_BYTES),
      0);

  // The keys derived by A and B should be different.
  assert(memcmp(ephemeral_public_key_for_a, ephemeral_public_key_for_b,
                CUBICRYPT_KX_PUBLIC_KEY_BYTES) != 0);
  assert(memcmp(a_primary_key, b_primary_key, CUBICRYPT_PRIMARY_KEY_BYTES) !=
         0);

  // The shared secret produced by X25519 is always below 2^255, thus, the top
  // bit is always zero. Cubicrypt's key exchange should not reveal such
  // structures. We only test for the simple case here by generating keys until
  // the top bit is not zero, which won't terminate unless the implementation
  // applies some mixing.
  uint8_t primary_key[CUBICRYPT_PRIMARY_KEY_BYTES];
  uint8_t ephemeral_public_key[CUBICRYPT_KX_PUBLIC_KEY_BYTES];
  do {
    assert(cubicrypt_kx_generate_primary_key(primary_key, a_public_key,
                                             ephemeral_public_key));
  } while (primary_key[CUBICRYPT_PRIMARY_KEY_BYTES - 1] < 0x80u);

  // Lastly, test a statically generated test vector.
  memset(primary_key, 0, CUBICRYPT_PRIMARY_KEY_BYTES);
  assert(is_valid_private_key(sat_private_key));
  assert(is_valid_public_key(sat_public_key));
  assert(is_valid_private_key(gnd_private_key));
  assert(is_valid_public_key(gnd_public_key));
  assert(cubicrypt_kx_derive_primary_key(primary_key, sat_public_key,
                                         gnd_public_key, gnd_private_key));
  assert_eq(
      memcmp(primary_key, expected_primary_key, CUBICRYPT_PRIMARY_KEY_BYTES),
      0);
  memset(primary_key, 0, CUBICRYPT_PRIMARY_KEY_BYTES);
  assert(cubicrypt_kx_derive_primary_key(primary_key, gnd_public_key,
                                         sat_public_key, sat_private_key));
  assert_eq(
      memcmp(primary_key, expected_primary_key, CUBICRYPT_PRIMARY_KEY_BYTES),
      0);

#endif
}
