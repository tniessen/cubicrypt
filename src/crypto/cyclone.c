#include "primitives.h"

#include "../../include/cubicrypt.h"

#define CUBICRYPT_EXTERN extern
#include "../../include/cubicrypt/external.h"

#include <assert.h>
#include <string.h>

#include <aead/gcm.h>
#include <cipher/aes.h>
#include <mac/gmac.h>

#ifndef CUBICRYPT_NO_KEY_EXCHANGE
#  include <ecc/x25519.h>

// We compile with -pedantic, but Cyclone does not strictly conform to C99.
#  pragma GCC diagnostic push
#  pragma GCC diagnostic warning "-Wpedantic"
#  include <hash/sha256.h>
#  pragma GCC diagnostic pop

#  include "cyclone-trng-test.h"
#  ifdef CUBICRYPT_HAVE_CYCLONE_TRNG
#    include <rng/trng.h>
#  else
#    include <sys/random.h>  // getentropy()
#  endif

#  include "x25519-helper.h"
#endif

bool cubicrypt_aes_256_cipher(const void* key, const void* block, void* out) {
  AesContext ctx;
  if (aesInit(&ctx, key, CUBICRYPT_PRIMARY_KEY_BYTES) != 0) {
    return false;
  }
  aesEncryptBlock(&ctx, block, out);
  aesDeinit(&ctx);
  return true;
}

bool cubicrypt_aes_128_gcm_encrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* plaintext, size_t plaintext_size,
                                   void* out, void* auth_tag) {
  AesContext aes;
  if (aesInit(&aes, key, CUBICRYPT_SESSION_KEY_BYTES) != 0) return false;
  GcmContext gcm;
  if (gcmInit(&gcm, AES_CIPHER_ALGO, &aes) != 0) {
    aesDeinit(&aes);
    return false;
  }
  error_t ret = gcmEncrypt(&gcm, iv, CUBICRYPT_AES_GCM_IV_BYTES, aad, aad_size,
                           plaintext, out, plaintext_size, auth_tag,
                           CUBICRYPT_AES_GCM_AUTH_TAG_BYTES);
  aesDeinit(&aes);
  return ret == 0;
}

bool cubicrypt_aes_128_gcm_decrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* ciphertext,
                                   size_t ciphertext_size, void* out,
                                   const void* auth_tag, bool* result) {
  AesContext aes;
  if (aesInit(&aes, key, CUBICRYPT_SESSION_KEY_BYTES) != 0) return false;
  GcmContext gcm;
  if (gcmInit(&gcm, AES_CIPHER_ALGO, &aes) != 0) {
    aesDeinit(&aes);
    return false;
  }
  error_t ret = gcmDecrypt(&gcm, iv, CUBICRYPT_AES_GCM_IV_BYTES, aad, aad_size,
                           ciphertext, out, ciphertext_size, auth_tag,
                           CUBICRYPT_AES_GCM_AUTH_TAG_BYTES);
  *result = (ret == 0);
  aesDeinit(&aes);
  return true;
}

bool cubicrypt_aes_128_gmac_compute(const void* key, const void* iv,
                                    const cubicrypt_iovecs* iovecs,
                                    void* auth_tag) {
  GmacContext gmac;
  // TODO: there does not appear to be any way to deinitialize a GmacContext,
  // even though it surely wraps an AesContext somehow, which has aesDeinit. Do
  // we need to perform any cleanup? Should we just erase &gmac?
  if (gmacInit(&gmac, AES_CIPHER_ALGO, key, CUBICRYPT_SESSION_KEY_BYTES) != 0) {
    return false;
  }
  if (gmacReset(&gmac, iv, CUBICRYPT_AES_GCM_IV_BYTES) != 0) {
    return false;
  }
  for (size_t i = 0; i < iovecs->n_bufs; ++i) {
    gmacUpdate(&gmac, iovecs->bufs[i].iov_base, iovecs->bufs[i].iov_len);
  }
  return gmacFinal(&gmac, auth_tag, CUBICRYPT_AES_GCM_AUTH_TAG_BYTES) == 0;
}

bool cubicrypt_aes_128_gmac_verify(const void* key, const void* iv,
                                   const cubicrypt_iovecs* iovecs,
                                   const void* auth_tag, bool* result) {
  uint8_t correct_auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  bool ok = cubicrypt_aes_128_gmac_compute(key, iv, iovecs, correct_auth_tag);
  if (ok) {
    // Cyclone does not appear to provide a function to verify GMAC tags nor a
    // function to compare two tags for equality. This comparison should usually
    // be constant-time.
    uint8_t mask = 0;
    for (size_t i = 0; i < CUBICRYPT_AES_GCM_AUTH_TAG_BYTES; ++i) {
      mask |= ((uint8_t*) auth_tag)[i] ^ correct_auth_tag[i];
    }
    *result = (mask == 0);
  }
  return ok;
}

#ifndef CUBICRYPT_NO_KEY_EXCHANGE

/** X25519(k, u) from RFC 7748. */
static bool x25519_scalar_mult(void* out, const void* private_key,
                               const void* public_key) {
  return x25519(out, private_key, public_key) == 0;
}

bool cubicrypt_x25519_keygen(void* public_key, void* private_key) {
  // If Cyclone is providing a TRNG, use it. Otherwise, hope that we have
  // getentropy() available.
#  ifdef CUBICRYPT_HAVE_CYCLONE_TRNG
  error_t ret = trngGetRandomData(private_key, CUBICRYPT_KX_PRIVATE_KEY_BYTES);
#  else
  int ret = getentropy(private_key, CUBICRYPT_KX_PRIVATE_KEY_BYTES);
#  endif
  if (ret != 0) return false;

  assert(SHA256_DIGEST_SIZE == CUBICRYPT_KX_PRIVATE_KEY_BYTES);
  if (sha256Compute(private_key, CUBICRYPT_KX_PRIVATE_KEY_BYTES, public_key) !=
      0) {
    return false;
  }
  x25519_clamp_private_key(private_key);
  uint8_t base_point[CUBICRYPT_X25519_SHARED_SECRET_BYTES] = { 9u };
  return x25519_scalar_mult(public_key, private_key, base_point);
}

bool cubicrypt_x25519_compute(void* shared_secret, const void* public_key,
                              const void* private_key) {
  return x25519_scalar_mult(shared_secret, private_key, public_key);
}

bool cubicrypt_x25519_mix(void* out, const void* ss, const void* pk0,
                          const void* pk1) {
  Sha256Context sha256;
  sha256Init(&sha256);
  sha256Update(&sha256, ss, CUBICRYPT_X25519_SHARED_SECRET_BYTES);
  sha256Update(&sha256, pk0, CUBICRYPT_KX_PUBLIC_KEY_BYTES);
  sha256Update(&sha256, pk1, CUBICRYPT_KX_PUBLIC_KEY_BYTES);
  sha256Final(&sha256, out);
  return true;
}

#endif
