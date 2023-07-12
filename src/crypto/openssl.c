#include "primitives.h"

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

#ifndef CUBICRYPT_NO_KEY_EXCHANGE

bool cubicrypt_x25519_keygen(void* public_key, void* private_key) {
  EVP_PKEY* pkey = NULL;

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
  if (ctx == NULL) return false;
  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return false;
  }
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return false;
  }
  EVP_PKEY_CTX_free(ctx);

  size_t len = CUBICRYPT_KX_PRIVATE_KEY_BYTES;
  if (EVP_PKEY_get_raw_private_key(pkey, private_key, &len) != 1) {
    EVP_PKEY_free(pkey);
    return false;
  }
  assert(len == CUBICRYPT_KX_PRIVATE_KEY_BYTES);
  len = CUBICRYPT_KX_PUBLIC_KEY_BYTES;
  if (EVP_PKEY_get_raw_public_key(pkey, public_key, &len) != 1) {
    EVP_PKEY_free(pkey);
    return false;
  }
  assert(len == CUBICRYPT_KX_PUBLIC_KEY_BYTES);
  EVP_PKEY_free(pkey);
  return true;
}

bool cubicrypt_x25519_compute(void* shared_secret, const void* public_key,
                              const void* private_key) {
  EVP_PKEY* pkey_public = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, NULL, public_key, CUBICRYPT_KX_PUBLIC_KEY_BYTES);
  EVP_PKEY* pkey_private = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, NULL, private_key, CUBICRYPT_KX_PRIVATE_KEY_BYTES);
  if (pkey_public == NULL || pkey_private == NULL) {
    EVP_PKEY_free(pkey_public);
    EVP_PKEY_free(pkey_private);
    return false;
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_private, NULL);
  size_t len = CUBICRYPT_X25519_SHARED_SECRET_BYTES;
  bool ok = ctx != NULL && EVP_PKEY_derive_init(ctx) == 1 &&
            EVP_PKEY_derive_set_peer(ctx, pkey_public) == 1 &&
            EVP_PKEY_derive(ctx, shared_secret, &len) == 1;
  assert(!ok || len == CUBICRYPT_X25519_SHARED_SECRET_BYTES);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey_public);
  EVP_PKEY_free(pkey_private);
  return ok;
}

bool cubicrypt_x25519_mix(void* out, const void* in) {
  return EVP_Q_digest(NULL, "SHA256", NULL, in,
                      CUBICRYPT_X25519_SHARED_SECRET_BYTES, out, NULL) == 1;
}

#endif
