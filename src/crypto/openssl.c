#include "aes.h"

#include "../../include/cubicrypt.h"

#include <assert.h>
#include <openssl/evp.h>

bool cubicrypt_aes_256_cipher(const void* key, const void* block, void* out) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    return false;
  }

  int outlen;
  bool ok = (EVP_EncryptInit(ctx, EVP_aes_256_ecb(), key, NULL) == 1) &&
            (EVP_EncryptUpdate(ctx, out, &outlen, block, 16) == 1);
  assert(!ok || outlen == 16);
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

static inline EVP_CIPHER_CTX* setup_aes_128_gcm_encrypt(const void* key,
                                                        const void* iv) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx != NULL) {
    if (EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      ctx = NULL;
    }
  }
  return ctx;
}

static inline EVP_CIPHER_CTX* setup_aes_128_gcm_decrypt(const void* key,
                                                        const void* iv,
                                                        const void* auth_tag) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx != NULL) {
    if (EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            CUBICRYPT_AES_GCM_AUTH_TAG_BYTES,
                            (void*) auth_tag) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      ctx = NULL;
    }
  }
  return ctx;
}

static inline bool do_aes_128_gcm_cipher(EVP_CIPHER_CTX* ctx, const void* aad,
                                         size_t aad_size, const void* input,
                                         size_t input_size, void* out) {
  int outlen;
  if (aad_size != 0) {
    if (EVP_CipherUpdate(ctx, NULL, &outlen, aad, aad_size) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    assert((size_t) outlen == aad_size);
  }

  if (EVP_CipherUpdate(ctx, out, &outlen, input, input_size) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  assert((size_t) outlen == input_size);
  return true;
}

static inline bool append_aes_128_gcm_aad(EVP_CIPHER_CTX* ctx,
                                          const cubicrypt_iovecs* iovecs) {
  for (size_t i = 0; i < iovecs->n_bufs; i++) {
    cubicrypt_iovec* v = &iovecs->bufs[i];
    if (v->iov_len != 0) {
      int outlen;
      if (EVP_CipherUpdate(ctx, NULL, &outlen, v->iov_base, v->iov_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      assert((size_t) outlen == v->iov_len);
    }
  }
  return true;
}

static inline bool finish_aes_128_gcm_encrypt(EVP_CIPHER_CTX* ctx,
                                              void* auth_tag) {
  int outlen;
  if (EVP_EncryptFinal_ex(ctx, NULL, &outlen) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  assert(outlen == 0);

  bool ok =
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                          CUBICRYPT_AES_GCM_AUTH_TAG_BYTES, auth_tag) == 1;
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

static inline bool finish_aes_128_gcm_decrypt(EVP_CIPHER_CTX* ctx,
                                              bool* result) {
  int outlen = 0;
  *result = (EVP_DecryptFinal_ex(ctx, NULL, &outlen) == 1);
  assert(outlen == 0);
  EVP_CIPHER_CTX_free(ctx);
  return true;
}

bool cubicrypt_aes_128_gcm_encrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* plaintext, size_t plaintext_size,
                                   void* out, void* auth_tag) {
  EVP_CIPHER_CTX* ctx = setup_aes_128_gcm_encrypt(key, iv);
  return (ctx != NULL) &&
         do_aes_128_gcm_cipher(ctx, aad, aad_size, plaintext, plaintext_size,
                               out) &&
         finish_aes_128_gcm_encrypt(ctx, auth_tag);
}

bool cubicrypt_aes_128_gcm_decrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* ciphertext,
                                   size_t ciphertext_size, void* out,
                                   const void* auth_tag, bool* result) {
  EVP_CIPHER_CTX* ctx = setup_aes_128_gcm_decrypt(key, iv, auth_tag);
  return (ctx != NULL) &&
         do_aes_128_gcm_cipher(ctx, aad, aad_size, ciphertext, ciphertext_size,
                               out) &&
         finish_aes_128_gcm_decrypt(ctx, result);
}

bool cubicrypt_aes_128_gmac_compute(const void* key, const void* iv,
                                    const cubicrypt_iovecs* iovecs,
                                    void* auth_tag) {
  EVP_CIPHER_CTX* ctx = setup_aes_128_gcm_encrypt(key, iv);
  return (ctx != NULL) && append_aes_128_gcm_aad(ctx, iovecs) &&
         finish_aes_128_gcm_encrypt(ctx, auth_tag);
}

bool cubicrypt_aes_128_gmac_verify(const void* key, const void* iv,
                                   const cubicrypt_iovecs* iovecs,
                                   const void* auth_tag, bool* result) {
  EVP_CIPHER_CTX* ctx = setup_aes_128_gcm_decrypt(key, iv, auth_tag);
  return (ctx != NULL) && append_aes_128_gcm_aad(ctx, iovecs) &&
         finish_aes_128_gcm_decrypt(ctx, result);
}
