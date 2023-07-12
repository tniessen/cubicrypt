#include "primitives.h"

#include "../../include/cubicrypt.h"

#define CUBICRYPT_EXTERN extern
#include "../../include/cubicrypt/external.h"

#include <assert.h>

#include <mbedtls/aes.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/gcm.h>
#include <mbedtls/version.h>

#ifndef CUBICRYPT_NO_KEY_EXCHANGE
#  include <mbedtls/ecdh.h>
#  include <mbedtls/entropy.h>
#  include <mbedtls/mbedtls_config.h>
#  include <mbedtls/sha256.h>
#endif

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

#ifndef CUBICRYPT_NO_KEY_EXCHANGE

bool cubicrypt_x25519_keygen(void* public_key, void* private_key) {
  cubicrypt_mbedtls_entropy_func f_rng;
  void* f_rng_ctx;
#  ifndef MBEDTLS_NO_PLATFORM_ENTROPY
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);
  f_rng = mbedtls_entropy_func;
  f_rng_ctx = &entropy;
#  else
  if (!__cubicrypt_get_mbedtls_entropy_func(&f_rng, &f_rng_ctx)) {
    return false;
  }
#  endif

  const mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_CURVE25519;
  assert(mbedtls_ecdh_can_do(grp_id));

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  if (mbedtls_ecp_group_load(&grp, grp_id) != 0) {
    mbedtls_ecp_group_free(&grp);
    return false;
  }

  mbedtls_ecp_point q;
  mbedtls_ecp_point_init(&q);
  mbedtls_mpi d;
  mbedtls_mpi_init(&d);

  size_t olen;
  bool ok = mbedtls_ecdh_gen_public(&grp, &d, &q, f_rng, f_rng_ctx) == 0 &&
            mbedtls_mpi_write_binary_le(&d, private_key,
                                        CUBICRYPT_KX_PRIVATE_KEY_BYTES) == 0 &&
            mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_COMPRESSED,
                                           &olen, public_key,
                                           CUBICRYPT_KX_PUBLIC_KEY_BYTES) == 0;
  assert(!ok || olen == CUBICRYPT_KX_PUBLIC_KEY_BYTES);

#  ifndef MBEDTLS_NO_PLATFORM_ENTROPY
  mbedtls_entropy_free(&entropy);
#  endif

  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&q);
  mbedtls_mpi_free(&d);

  return ok;
}

bool cubicrypt_x25519_compute(void* shared_secret, const void* public_key,
                              const void* private_key) {
  cubicrypt_mbedtls_entropy_func f_rng;
  void* f_rng_ctx;
#  ifndef MBEDTLS_NO_PLATFORM_ENTROPY
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);
  f_rng = mbedtls_entropy_func;
  f_rng_ctx = &entropy;
#  else
  if (!__cubicrypt_get_mbedtls_entropy_func(&f_rng, &f_rng_ctx)) {
    return false;
  }
#  endif

  const mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_CURVE25519;
  assert(mbedtls_ecdh_can_do(grp_id));

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  if (mbedtls_ecp_group_load(&grp, grp_id) != 0) {
    mbedtls_ecp_group_free(&grp);
    return false;
  }

  mbedtls_ecp_point q;
  mbedtls_ecp_point_init(&q);
  mbedtls_mpi d;
  mbedtls_mpi_init(&d);
  mbedtls_mpi z;
  mbedtls_mpi_init(&z);

  bool ok =
      mbedtls_ecp_point_read_binary(&grp, &q, public_key,
                                    CUBICRYPT_KX_PUBLIC_KEY_BYTES) == 0 &&
      mbedtls_mpi_read_binary_le(&d, private_key,
                                 CUBICRYPT_KX_PRIVATE_KEY_BYTES) == 0 &&
      mbedtls_ecdh_compute_shared(&grp, &z, &q, &d, f_rng, f_rng_ctx) == 0 &&
      mbedtls_mpi_write_binary_le(&z, shared_secret,
                                  CUBICRYPT_X25519_SHARED_SECRET_BYTES) == 0;

#  ifndef MBEDTLS_NO_PLATFORM_ENTROPY
  mbedtls_entropy_free(&entropy);
#  endif

  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&q);
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&z);

  return ok;
}

bool cubicrypt_x25519_mix(void* out, const void* in) {
  return mbedtls_sha256(in, CUBICRYPT_X25519_SHARED_SECRET_BYTES, out, 0) == 0;
}

#endif
