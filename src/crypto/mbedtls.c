#include "aes.h"

#include "../../include/cubicrypt.h"

#include <assert.h>

#include <mbedtls/aes.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/gcm.h>
#include <mbedtls/version.h>

// Mbed TLS 3.0 supports GMAC, but not mbedtls_ct_memcmp(), which was added in
// the next minor release.
#if MBEDTLS_VERSION_NUMBER < 0x03010000
#  error "mbedtls version 3.1.0 or later is required"
#endif

bool cubicrypt_aes_256_cipher(const void* key, const void* block, void* out) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  bool ok = (mbedtls_aes_setkey_enc(&aes, key, 256) == 0 &&
             mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, block, out) == 0);

  mbedtls_aes_free(&aes);

  return ok;
}

bool cubicrypt_aes_128_gcm_encrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* plaintext, size_t plaintext_size,
                                   void* out, void* auth_tag) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
  if (ret != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }

  ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext_size, iv,
                                  12, aad, aad_size, plaintext, out,
                                  CUBICRYPT_AES_GCM_AUTH_TAG_BYTES, auth_tag);

  mbedtls_gcm_free(&gcm);

  return (ret == 0);
}

bool cubicrypt_aes_128_gcm_decrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* ciphertext,
                                   size_t ciphertext_size, void* out,
                                   const void* auth_tag, bool* result) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
  if (ret != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }

  ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_size, iv, 12, aad, aad_size,
                                 auth_tag, CUBICRYPT_AES_GCM_AUTH_TAG_BYTES,
                                 ciphertext, out);

  mbedtls_gcm_free(&gcm);

  *result = (ret == 0);

  return (ret == 0 || ret == MBEDTLS_ERR_GCM_AUTH_FAILED);
}

bool cubicrypt_aes_128_gmac_compute(const void* key, const void* iv,
                                    const cubicrypt_iovecs* iovecs,
                                    void* auth_tag) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128) != 0 ||
      mbedtls_gcm_starts(&gcm, MBEDTLS_GCM_ENCRYPT, iv, 12) != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }

  for (size_t i = 0; i < iovecs->n_bufs; i++) {
    cubicrypt_iovec* vec = &iovecs->bufs[i];
    if (vec->iov_len != 0) {
      if (mbedtls_gcm_update_ad(&gcm, vec->iov_base, vec->iov_len) != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
      }
    }
  }

  size_t outlen = 0;
  int ret = mbedtls_gcm_finish(&gcm, NULL, 0, &outlen, auth_tag,
                               CUBICRYPT_AES_GCM_AUTH_TAG_BYTES);
  assert(outlen == 0);
  mbedtls_gcm_free(&gcm);
  return (ret == 0);
}

bool cubicrypt_aes_128_gmac_verify(const void* key, const void* iv,
                                   const cubicrypt_iovecs* iovecs,
                                   const void* auth_tag, bool* result) {
  uint8_t correct_auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  if (!cubicrypt_aes_128_gmac_compute(key, iv, iovecs, correct_auth_tag)) {
    return false;
  }

  *result = mbedtls_ct_memcmp(auth_tag, correct_auth_tag,
                              CUBICRYPT_AES_GCM_AUTH_TAG_BYTES) == 0;

  return true;
}
