#include "aes.h"

#include "../../include/cubicrypt.h"

#include <assert.h>
#include <gcrypt.h>
#include <stdint.h>

bool cubicrypt_aes_256_cipher(const void* key, const void* block, void* out) {
  gcry_cipher_hd_t hd;
  gcry_error_t err =
      gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
  if (err != GPG_ERR_NO_ERROR) {
    return false;
  }

  bool ok = (gcry_cipher_setkey(hd, key, 32) == GPG_ERR_NO_ERROR) &&
            (gcry_cipher_encrypt(hd, out, 16, block, 16) == GPG_ERR_NO_ERROR);
  gcry_cipher_close(hd);
  return ok;
}

bool cubicrypt_aes_128_gcm_encrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* plaintext, size_t plaintext_size,
                                   void* out, void* auth_tag) {
  gcry_cipher_hd_t hd;
  if (gcry_cipher_open(&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0) !=
      GPG_ERR_NO_ERROR) {
    return false;
  }

  if (gcry_cipher_setkey(hd, key, 16) != GPG_ERR_NO_ERROR ||
      gcry_cipher_setiv(hd, iv, 12) != GPG_ERR_NO_ERROR ||
      gcry_cipher_authenticate(hd, aad, aad_size) != GPG_ERR_NO_ERROR ||
      gcry_cipher_final(hd) != GPG_ERR_NO_ERROR ||
      gcry_cipher_encrypt(hd, out, plaintext_size, plaintext, plaintext_size) !=
          GPG_ERR_NO_ERROR) {
    gcry_cipher_close(hd);
    return false;
  }

  gcry_error_t err =
      gcry_cipher_gettag(hd, auth_tag, CUBICRYPT_AES_GCM_AUTH_TAG_BYTES);
  gcry_cipher_close(hd);
  return (err == GPG_ERR_NO_ERROR);
}

bool cubicrypt_aes_128_gcm_decrypt(const void* key, const void* iv,
                                   const void* aad, size_t aad_size,
                                   const void* ciphertext,
                                   size_t ciphertext_size, void* out,
                                   const void* auth_tag, bool* result) {
  gcry_cipher_hd_t hd;
  if (gcry_cipher_open(&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0) !=
      GPG_ERR_NO_ERROR) {
    return false;
  }

  if (gcry_cipher_setkey(hd, key, 16) != GPG_ERR_NO_ERROR ||
      gcry_cipher_setiv(hd, iv, 12) != GPG_ERR_NO_ERROR ||
      gcry_cipher_authenticate(hd, aad, aad_size) != GPG_ERR_NO_ERROR ||
      gcry_cipher_final(hd) != GPG_ERR_NO_ERROR ||
      gcry_cipher_decrypt(hd, out, ciphertext_size, ciphertext,
                          ciphertext_size) != GPG_ERR_NO_ERROR) {
    gcry_cipher_close(hd);
    return false;
  }

  gcry_error_t err =
      gcry_cipher_checktag(hd, auth_tag, CUBICRYPT_AES_GCM_AUTH_TAG_BYTES);
  *result = (err == GPG_ERR_NO_ERROR);
  gcry_cipher_close(hd);
  return (err == GPG_ERR_NO_ERROR || gcry_err_code(err) == GPG_ERR_CHECKSUM);
}

static inline bool process_aes_128_gmac(gcry_mac_hd_t* hd, const void* key,
                                        const void* iv,
                                        const cubicrypt_iovecs* iovecs) {
  gcry_error_t err = gcry_mac_open(hd, GCRY_MAC_GMAC_AES, 0, NULL);
  if (err != GPG_ERR_NO_ERROR) {
    return false;
  }

  if (gcry_mac_setkey(*hd, key, 16) != GPG_ERR_NO_ERROR ||
      gcry_mac_setiv(*hd, iv, 12) != GPG_ERR_NO_ERROR) {
    gcry_mac_close(*hd);
    return false;
  }

  for (size_t i = 0; i < iovecs->n_bufs; i++) {
    cubicrypt_iovec* v = &iovecs->bufs[i];
    if (v->iov_len != 0) {
      err = gcry_mac_write(*hd, v->iov_base, v->iov_len);
      if (err != GPG_ERR_NO_ERROR) {
        gcry_mac_close(*hd);
        return false;
      }
    }
  }

  return true;
}

bool cubicrypt_aes_128_gmac_compute(const void* key, const void* iv,
                                    const cubicrypt_iovecs* iovecs,
                                    void* auth_tag) {
  gcry_mac_hd_t hd;
  if (!process_aes_128_gmac(&hd, key, iv, iovecs)) {
    return false;
  }

  size_t length = CUBICRYPT_AES_GCM_AUTH_TAG_BYTES;
  gcry_error_t err = gcry_mac_read(hd, auth_tag, &length);
  assert(err != GPG_ERR_NO_ERROR || length == CUBICRYPT_AES_GCM_AUTH_TAG_BYTES);
  gcry_mac_close(hd);

  return (err == GPG_ERR_NO_ERROR);
}

bool cubicrypt_aes_128_gmac_verify(const void* key, const void* iv,
                                   const cubicrypt_iovecs* iovecs,
                                   const void* auth_tag, bool* result) {
  gcry_mac_hd_t hd;
  if (!process_aes_128_gmac(&hd, key, iv, iovecs)) {
    return false;
  }

  gcry_error_t err =
      gcry_mac_verify(hd, auth_tag, CUBICRYPT_AES_GCM_AUTH_TAG_BYTES);
  *result = (err == GPG_ERR_NO_ERROR);
  gcry_mac_close(hd);

  return (err == GPG_ERR_NO_ERROR || gcry_err_code(err) == GPG_ERR_CHECKSUM);
}