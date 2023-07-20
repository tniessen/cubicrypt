#include "primitives.h"

#include "../../include/cubicrypt.h"

#include <nettle/aes.h>
#include <nettle/gcm.h>
#include <nettle/memops.h>
#include <stdint.h>
#include <string.h>

#ifndef CUBICRYPT_NO_KEY_EXCHANGE
#  include <nettle/curve25519.h>
#  include <nettle/sha2.h>

#  include <unistd.h>  // getentropy()

#  include "x25519-helper.h"
#endif

bool cubicrypt_aes_256_cipher(const void* key, const void* block, void* out) {
  struct aes256_ctx ctx;
  aes256_set_encrypt_key(&ctx, key);
  aes256_encrypt(&ctx, 16, out, block);
  return true;
}

bool cubicrypt_aes_128_gcm_encrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* plaintext, size_t plaintext_size,
                                   void* out, void* auth_tag) {
  struct gcm_aes128_ctx ctx;
  gcm_aes128_set_key(&ctx, key);
  gcm_aes128_set_iv(&ctx, 12, iv);
  gcm_aes128_update(&ctx, aad_size, aad);
  gcm_aes128_encrypt(&ctx, plaintext_size, out, plaintext);
  gcm_aes128_digest(&ctx, CUBICRYPT_AES_GCM_AUTH_TAG_BYTES, auth_tag);
  return true;
}

bool cubicrypt_aes_128_gcm_decrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* ciphertext,
                                   size_t ciphertext_size, void* out,
                                   const void* auth_tag, bool* result) {
  struct gcm_aes128_ctx ctx;
  gcm_aes128_set_key(&ctx, key);
  gcm_aes128_set_iv(&ctx, 12, iv);
  gcm_aes128_update(&ctx, aad_size, aad);
  gcm_aes128_decrypt(&ctx, ciphertext_size, out, ciphertext);

  uint8_t correct_auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  gcm_aes128_digest(&ctx, CUBICRYPT_AES_GCM_AUTH_TAG_BYTES, correct_auth_tag);
  *result = (memeql_sec(auth_tag, correct_auth_tag,
                        CUBICRYPT_AES_GCM_AUTH_TAG_BYTES) != 0);

  return true;
}

bool cubicrypt_aes_128_gmac_compute(const void* key, const void* iv,
                                    const cubicrypt_iovecs* iovecs,
                                    void* auth_tag) {
  struct gcm_aes128_ctx ctx;

  gcm_aes128_set_key(&ctx, key);
  gcm_aes128_set_iv(&ctx, 12, iv);

  // nettle requires that each call to gcm_aes128_update() except the last
  // passes a number of bytes that is a multiple of the block size.
  uint8_t remaining_buf[16];
  size_t remaining_len = 0;

  for (size_t i = 0; i < iovecs->n_bufs; i++) {
    const cubicrypt_iovec* vec = &iovecs->bufs[i];
    if (vec->iov_len != 0) {
      // First, if there is any data remaining from previous iterations, try to
      // flush it.
      const uint8_t* base = vec->iov_base;
      size_t offset = 0;
      if (remaining_len != 0) {
        size_t len = sizeof(remaining_buf) - remaining_len;
        if (vec->iov_len >= len) {
          // Flush the remaining data.
          memcpy(remaining_buf + remaining_len, base, len);
          gcm_aes128_update(&ctx, sizeof(remaining_buf), remaining_buf);
          remaining_len = 0;
          offset = len;
        } else {
          // Not enough new data to flush the existing remaining data.
          memcpy(remaining_buf + remaining_len, base, vec->iov_len);
          remaining_len += vec->iov_len;
          continue;
        }
      }

      // All remaining data from previous iterations has been flushed. Now
      // process as many blocks as possible at once.
      size_t n_blocks = (vec->iov_len - offset) / 16;
      if (n_blocks != 0) {
        gcm_aes128_update(&ctx, n_blocks * 16, base + offset);
        offset += n_blocks * 16;
      }

      // If there is any data remaining, store it for the next iteration.
      if (offset < vec->iov_len) {
        remaining_len = vec->iov_len - offset;
        memcpy(remaining_buf, base + offset, remaining_len);
      }
    }
  }

  if (remaining_len != 0) {
    gcm_aes128_update(&ctx, remaining_len, remaining_buf);
  }

  gcm_aes128_digest(&ctx, CUBICRYPT_AES_GCM_AUTH_TAG_BYTES, auth_tag);

  return true;
}

bool cubicrypt_aes_128_gmac_verify(const void* key, const void* iv,
                                   const cubicrypt_iovecs* iovecs,
                                   const void* auth_tag, bool* result) {
  uint8_t correct_auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  if (!cubicrypt_aes_128_gmac_compute(key, iv, iovecs, correct_auth_tag)) {
    return false;
  }

  *result = (memeql_sec(auth_tag, correct_auth_tag,
                        CUBICRYPT_AES_GCM_AUTH_TAG_BYTES) != 0);
  return true;
}

#ifndef CUBICRYPT_NO_KEY_EXCHANGE

bool cubicrypt_x25519_keygen(void* public_key, void* private_key) {
  // TODO: reconsider using getentropy() without a DRBG here
  int ret = getentropy(private_key, CUBICRYPT_KX_PRIVATE_KEY_BYTES);
  if (ret != 0) return false;
  x25519_clamp_private_key(private_key);
  curve25519_mul_g(public_key, private_key);
  return true;
}

bool cubicrypt_x25519_compute(void* shared_secret, const void* public_key,
                              const void* private_key) {
  curve25519_mul(shared_secret, private_key, public_key);
  return true;
}

bool cubicrypt_x25519_mix(void* out, const void* ss, const void* pk0,
                          const void* pk1) {
  struct sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, CUBICRYPT_X25519_SHARED_SECRET_BYTES, ss);
  sha256_update(&ctx, CUBICRYPT_KX_PUBLIC_KEY_BYTES, pk0);
  sha256_update(&ctx, CUBICRYPT_KX_PUBLIC_KEY_BYTES, pk1);
  sha256_digest(&ctx, SHA256_DIGEST_SIZE, out);
  return true;
}

#endif
