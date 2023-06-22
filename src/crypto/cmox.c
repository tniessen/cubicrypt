#include "aes.h"

#include "../../include/cubicrypt.h"

#include <assert.h>
#include <string.h>
#include <cmox_crypto.h>

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
