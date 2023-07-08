#ifndef __CRYPTO_X25519_HELPER_H__
#define __CRYPTO_X25519_HELPER_H__

#include <stdint.h>

static inline void x25519_clamp_private_key(uint8_t private_key[32]) {
  private_key[0] &= 0xf8;
  private_key[31] &= 0x7f;
  private_key[31] |= 0x40;
}

#endif  // __CRYPTO_X25519_HELPER_H__
