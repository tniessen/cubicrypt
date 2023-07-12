#include "primitives.h"

#include "../../include/cubicrypt.h"

#define CUBICRYPT_EXTERN extern
#include "../../include/cubicrypt/external.h"

#include <assert.h>
#include <string.h>
#include <cmox_crypto.h>

#ifndef CUBICRYPT_NO_KEY_EXCHANGE
#  include "x25519-helper.h"
#endif

bool cubicrypt_aes_256_cipher(const void* key, const void* block, void* out) {
  size_t outlen;
  cmox_cipher_retval_t ret =
      cmox_cipher_encrypt(CMOX_AESFAST_ECB_ENC_ALGO, block, 16, key,
                          CMOX_CIPHER_256_BIT_KEY, NULL, 0, out, &outlen);
  return (ret == CMOX_CIPHER_SUCCESS);
}

static inline cmox_cipher_handle_t* setup_aes_128_gcm(
    cmox_gcm_handle_t* gcm_handle, cmox_gcm_impl_t impl, const void* key,
    const void* iv) {
  cmox_cipher_handle_t* h = cmox_gcm_construct(gcm_handle, impl);
  if (h != NULL) {
    // TODO: if cmox_cipher_init fails, do we have to call cmox_cipher_cleanup?
    if (cmox_cipher_init(h) != CMOX_CIPHER_SUCCESS) return NULL;

    if (cmox_cipher_setTagLen(h, CUBICRYPT_AES_GCM_AUTH_TAG_BYTES) !=
            CMOX_CIPHER_SUCCESS ||
        cmox_cipher_setKey(h, key, CMOX_CIPHER_128_BIT_KEY) !=
            CMOX_CIPHER_SUCCESS ||
        cmox_cipher_setIV(h, iv, CUBICRYPT_AES_GCM_IV_BYTES) !=
            CMOX_CIPHER_SUCCESS) {
      cmox_cipher_cleanup(h);
      h = NULL;
    }
  }
  return h;
}

static inline bool do_aes_128_gcm_cipher(cmox_cipher_handle_t* h, const void* a,
                                         size_t a_size, const void* m,
                                         size_t m_size, void* out) {
  size_t outlen;
  if (cmox_cipher_appendAD(h, a, a_size) != CMOX_CIPHER_SUCCESS ||
      cmox_cipher_append(h, m, m_size, out, &outlen) != CMOX_CIPHER_SUCCESS) {
    cmox_cipher_cleanup(h);
    return false;
  }
  assert(outlen == m_size);
  return true;
}

static inline bool append_aes_128_gcm_aad(cmox_cipher_handle_t* h,
                                          const cubicrypt_iovecs* iovecs) {
  // CMOX requires that each call to cmox_cipher_appendAD() except the last
  // passes a number of bytes that is a multiple of the block size. Of course,
  // ST does not document this, nor do they provide the source code, so this
  // conclusion is based on trial and error with CMOX v4.1.0.
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
          if (cmox_cipher_appendAD(h, remaining_buf, sizeof(remaining_buf)) !=
              CMOX_CIPHER_SUCCESS) {
            cmox_cipher_cleanup(h);
            return false;
          }
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
        if (cmox_cipher_appendAD(h, base + offset, n_blocks * 16) !=
            CMOX_CIPHER_SUCCESS) {
          cmox_cipher_cleanup(h);
          return false;
        }
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
    if (cmox_cipher_appendAD(h, remaining_buf, remaining_len) !=
        CMOX_CIPHER_SUCCESS) {
      cmox_cipher_cleanup(h);
      return false;
    }
  }

  return true;
}

static inline bool finish_aes_128_gcm_enc(cmox_cipher_handle_t* h,
                                          void* auth_tag) {
  size_t outlen;
  bool ok =
      (cmox_cipher_generateTag(h, auth_tag, &outlen) == CMOX_CIPHER_SUCCESS);
  assert(outlen == CUBICRYPT_AES_GCM_AUTH_TAG_BYTES || !ok);
  if (cmox_cipher_cleanup(h) != CMOX_CIPHER_SUCCESS) ok = false;
  return ok;
}

static inline bool finish_aes_128_gcm_dec(cmox_cipher_handle_t* h,
                                          const void* auth_tag, bool* result) {
  uint32_t fault = CMOX_CIPHER_AUTH_FAIL;
  cmox_cipher_retval_t ret = cmox_cipher_verifyTag(h, auth_tag, &fault);
  // TODO: is the fault value equivalent to our interpretation of the result?
  *result = (fault == CMOX_CIPHER_AUTH_SUCCESS);
  if (cmox_cipher_cleanup(h) != CMOX_CIPHER_SUCCESS) {
    return false;
  }
  // TODO: is this correct? It's undocumented if it is
  return (ret == CMOX_CIPHER_AUTH_SUCCESS || ret == CMOX_CIPHER_AUTH_FAIL);
}

bool cubicrypt_aes_128_gcm_encrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* plaintext, size_t plaintext_size,
                                   void* out, void* auth_tag) {
  cmox_gcm_handle_t gcm_handle;
  cmox_cipher_handle_t* cipher_handle =
      setup_aes_128_gcm(&gcm_handle, CMOX_AES_GCM_ENC, key, iv);
  return (cipher_handle != NULL) &&
         do_aes_128_gcm_cipher(cipher_handle, aad, aad_size, plaintext,
                               plaintext_size, out) &&
         finish_aes_128_gcm_enc(cipher_handle, auth_tag);
}

bool cubicrypt_aes_128_gcm_decrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* ciphertext,
                                   size_t ciphertext_size, void* out,
                                   const void* auth_tag, bool* result) {
  cmox_gcm_handle_t gcm_handle;
  cmox_cipher_handle_t* cipher_handle =
      setup_aes_128_gcm(&gcm_handle, CMOX_AES_GCM_DEC, key, iv);
  return (cipher_handle != NULL) &&
         do_aes_128_gcm_cipher(cipher_handle, aad, aad_size, ciphertext,
                               ciphertext_size, out) &&
         finish_aes_128_gcm_dec(cipher_handle, auth_tag, result);
}

bool cubicrypt_aes_128_gmac_compute(const void* key, const void* iv,
                                    const cubicrypt_iovecs* iovecs,
                                    void* auth_tag) {
  cmox_gcm_handle_t gcm_handle;
  cmox_cipher_handle_t* cipher_handle =
      setup_aes_128_gcm(&gcm_handle, CMOX_AES_GCM_ENC, key, iv);
  return (cipher_handle != NULL) &&
         append_aes_128_gcm_aad(cipher_handle, iovecs) &&
         finish_aes_128_gcm_enc(cipher_handle, auth_tag);
}

bool cubicrypt_aes_128_gmac_verify(const void* key, const void* iv,
                                   const cubicrypt_iovecs* iovecs,
                                   const void* auth_tag, bool* result) {
  cmox_gcm_handle_t gcm_handle;
  cmox_cipher_handle_t* cipher_handle =
      setup_aes_128_gcm(&gcm_handle, CMOX_AES_GCM_DEC, key, iv);
  return (cipher_handle != NULL) &&
         append_aes_128_gcm_aad(cipher_handle, iovecs) &&
         finish_aes_128_gcm_dec(cipher_handle, auth_tag, result);
}

#ifndef CUBICRYPT_NO_KEY_EXCHANGE

/** X25519(k, u) from RFC 7748. */
static bool x25519_scalar_mult(void* out, const void* private_key,
                               const void* public_key) {
  // How big should the buffer be? As usual, the CMOX library documentation is
  // vastly insufficient, and of course the source code is not available at the
  // time of writing. Trial and error on a STM32L432KC with X-CUBE-CRYPTOLIB
  // v4.1.0 and the default configuration suggests that 496 bytes are enough
  // (but 495 are not). However, the implementation of the legacy function
  // C25519keyExchange() in legacy_v3/src/ecc/legacy_v3_c25519.c, which is part
  // of X-CUBE-CRYPTOLIB v4.1.0, uses the expression "496 + 68" for the buffer
  // size, so we will blindly trust it for now.
  uint8_t buf[496 + 68];
  cmox_ecc_handle_t ctx;
  size_t ss_len;
  cmox_ecc_construct(&ctx, CMOX_ECC256_MATH_FUNCS, buf, sizeof(buf));
  bool ok = cmox_ecdh(&ctx, CMOX_ECC_CURVE25519, private_key,
                      CMOX_ECC_CURVE25519_PRIVKEY_LEN, public_key,
                      CMOX_ECC_CURVE25519_PUBKEY_LEN, out,
                      &ss_len) == CMOX_ECC_SUCCESS &&
            ss_len == CMOX_ECC_CURVE25519_SECRET_LEN;
  cmox_ecc_cleanup(&ctx);
  return ok;
}

static inline bool cubicrypt_sha256(const void* in, size_t in_size, void* out) {
  size_t out_size;
  return cmox_hash_compute(CMOX_SHA256_ALGO, in, in_size, out, CMOX_SHA256_SIZE,
                           &out_size) == CMOX_HASH_SUCCESS &&
         out_size == CMOX_SHA256_SIZE;
}

static inline bool cubicrypt_secure_random_256bits(void* out) {
  // Unfortunately, while CMOX implements a DRBG, it does not expose a
  // cryptographically secure source of entropy to seed the DRBG with. Many
  // Cortex-M devices have a TRNG, but we cannot reasonably interface with the
  // HAL from here, so we have to leave it up to the application to provide
  // entropy.

  // We don't want to force the application to produce perfect randomness.
  // Instead, we provide a 256-bit buffer that the application can fill with
  // any amount of entropy, and we take care of accumulating entropy until we
  // produce a 256-bit value that we consider to be sufficiently random.
  // Our DRBG is very simple. We effectively compute
  //
  //     SHA256(SHA256(...SHA256(SHA256(B0 || B1) || B2)...) || Bk)
  //
  // where B0 consists of 256 zero bits, and B1, ..., Bk are the 256-bit buffers
  // through which the application provides entropy.

  // Start with a 512-bit buffer containing zero entropy. We operate on its two
  // 256-bit halves independently except when we hash its contents.
  uint8_t buffer[64] = { 0u };
  uint32_t entropy_estimate = 0;
  const uint32_t max_entropy = 256;

  // Gather entropy until we have at least 256 bits. In each iteration, we gain
  // at least one bit of entropy unless an error occurs.
  uint32_t new_entropy;
  while ((new_entropy = __cubicrypt_secure_entropy(buffer + 32, 32)) != 0 &&
         new_entropy <= max_entropy &&
         cubicrypt_sha256(buffer, sizeof(buffer), out) &&
         (entropy_estimate += new_entropy) < max_entropy) {
    // Before retrying, overwrite the first half of the buffer with the hash
    // of this iteration's buffer.
    memcpy(buffer, out, 32);
  }

  memset(buffer, 0, sizeof(buffer));
  return entropy_estimate >= max_entropy;
}

bool cubicrypt_x25519_keygen(void* public_key, void* private_key) {
  // CMOX does not support X25519 key generation directly, but we can abuse
  // cmox_ecdh() for scalar multiplication and thus use it to derive the public
  // key from the private key, and generating the private key is relatively
  // straightforward from a random 256-bit sequence.
  if (!cubicrypt_secure_random_256bits(private_key)) return false;
  x25519_clamp_private_key(private_key);
  uint8_t base_point[CUBICRYPT_X25519_SHARED_SECRET_BYTES] = { 9u };
  return x25519_scalar_mult(public_key, private_key, base_point);
}

bool cubicrypt_x25519_compute(void* shared_secret, const void* public_key,
                              const void* private_key) {
  return x25519_scalar_mult(shared_secret, private_key, public_key);
}

bool cubicrypt_x25519_mix(void* out, const void* in) {
  assert(CUBICRYPT_X25519_SHARED_SECRET_BYTES == CMOX_SHA256_SIZE);
  return cubicrypt_sha256(in, CUBICRYPT_X25519_SHARED_SECRET_BYTES, out);
}

#endif
