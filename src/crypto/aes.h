#ifndef __CRYPTO__AES_H__
#define __CRYPTO__AES_H__

#include <stdbool.h>
#include <stddef.h>

/**
 * Computes the AES block cipher for a single block using a 256-bit key.
 *
 * This function is used only to derive 128-bit session keys. Within a session,
 * only 128-bit keys are used.
 */
bool cubicrypt_aes_256_cipher(const void* key, const void* block, void* out);

/**
 * Authenticated encryption using AES-GCM with a 128-bit key.
 */
bool cubicrypt_aes_128_gcm_encrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* plaintext, size_t plaintext_size,
                                   void* out, void* auth_tag);

/**
 * Authenticated decryption using AES-GCM with a 128-bit key.
 */
bool cubicrypt_aes_128_gcm_decrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* ciphertext,
                                   size_t ciphertext_size, void* out,
                                   const void* auth_tag, bool* result);

typedef struct cubicrypt_iovec {
  const void* iov_base;
  size_t iov_len;
} cubicrypt_iovec;

typedef struct cubicrypt_iovecs {
  cubicrypt_iovec* bufs;
  size_t n_bufs;
} cubicrypt_iovecs;

/**
 * Computes GMAC using AES-GCM with a 128-bit key.
 *
 * This function is used for frames that are not encrypted but only
 * authenticated.
 */
bool cubicrypt_aes_128_gmac_compute(const void* key, const void* iv,
                                    const cubicrypt_iovecs* iovecs,
                                    void* auth_tag);

/**
 * Verifies GMAC using AES-GCM with a 128-bit key.
 */
bool cubicrypt_aes_128_gmac_verify(const void* key, const void* iv,
                                   const cubicrypt_iovecs* iovecs,
                                   const void* auth_tag, bool* result);

#endif  // __CRYPTO__AES_H__
