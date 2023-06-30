#include "../include/cubicrypt.h"
#include "crypto/aes.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/** Copies a 32-bit unsigned integer to memory using big-endian encoding. */
static inline void encode_u32be(uint32_t value, uint8_t* out) {
  out[0] = (value >> 030) & 0xff;
  out[1] = (value >> 020) & 0xff;
  out[2] = (value >> 010) & 0xff;
  out[3] = (value >> 000) & 0xff;
}

/** Copies a 32-bit or 64-bit unsigned integer to a 128-bit field. */
static inline void encode_u128be(size_t value, uint8_t* out) {
  memset(out, 0, 16 - sizeof(size_t));
#if SIZE_MAX > UINT32_MAX
  encode_u32be((uint32_t) (value >> 32u), out + 8);
#endif
  encode_u32be((uint32_t) (value & UINT32_MAX), out + 12);
}

// TODO: if this is only used to check if x > max_u32(width), then we can just
// use (x >> width) != 0.
static inline uint32_t max_u32(uint8_t width) {
  assert(width > 0 && width <= 32);
  return (width == 32) ? ((uint32_t) -1) : ((1u << (uint32_t) width) - 1);
}

static inline bool params_invalid(const cubicrypt_params* params) {
  return params->session_id_bits < CUBICRYPT_MIN_SESSION_ID_BITS ||
         params->session_id_bits > CUBICRYPT_MAX_SESSION_ID_BITS ||
         params->frame_iv_bits < CUBICRYPT_MIN_FRAME_IV_BITS ||
         params->frame_iv_bits > CUBICRYPT_MAX_FRAME_IV_BITS;
}

/**
 * Computes the session key based on a given primary key and the session id.
 */
static bool compute_session_key(const void* primary_key, uint32_t session_id,
                                void* session_key) {
  uint8_t plaintext[CUBICRYPT_SESSION_KEY_BYTES] = { 0 };
  encode_u32be(session_id, plaintext + CUBICRYPT_SESSION_KEY_BYTES - 4);
  return cubicrypt_aes_256_cipher(primary_key, plaintext, session_key);
}

/**
 * Computes the IV for a specific frame.
 */
static inline void compute_iv(uint32_t count, bool is_encrypted, uint8_t* iv) {
  // Reserved.
  memset(iv, 0, 4);
  // Flags.
  encode_u32be(((uint32_t) !is_encrypted) << 31u, iv + 4);
  // Frame counter.
  encode_u32be(count, iv + 8);
}

#define AES_GCM_BYTES_PER_BLOCK 16

typedef struct cubicrypt_padded {
  cubicrypt_iovecs iovecs;
  cubicrypt_iovec bufs[4];
  uint8_t prefix[AES_GCM_BYTES_PER_BLOCK];
} cubicrypt_padded;

static const uint8_t padding_zero[AES_GCM_BYTES_PER_BLOCK];

/**
 * Produces encode_u128be(aad_size) || aad || padding || body, where padding is
 * the shortest sequence of zeros such that the length of aad || padding is a
 * multiple of the AES-GCM block size (16 bytes).
 *
 * It is important to note that the IV contains a bit that indicates whether the
 * frame is encrypted or not. Otherwise, if we pad the AAD for auth-only frames,
 * we would not be able to distinguish it from empty encrypted frames with the
 * same AAD.
 */
static inline void pad_for_aad(cubicrypt_padded* p, const void* aad,
                               size_t aad_size, const void* body,
                               size_t body_size) {
  const size_t block_size = AES_GCM_BYTES_PER_BLOCK;
  p->iovecs.bufs = p->bufs;
  p->iovecs.n_bufs = 4;
  encode_u128be(aad_size, p->prefix);
  p->bufs[0].iov_base = p->prefix;
  p->bufs[0].iov_len = sizeof(p->prefix);
  p->bufs[1].iov_base = aad;
  p->bufs[1].iov_len = aad_size;
  p->bufs[2].iov_base = padding_zero;
  p->bufs[2].iov_len = (block_size - (aad_size % block_size)) % block_size;
  p->bufs[3].iov_base = body;
  p->bufs[3].iov_len = body_size;
}

cubicrypt_err cubicrypt_out_init(
    cubicrypt_out_ctx* ctx, const void* primary_key,
    const cubicrypt_params* params,
    cubicrypt_session_persistent_load_fn load_state,
    cubicrypt_session_persistent_save_fn save_state, void* storage_user_data) {
  if (ctx == NULL || primary_key == NULL || params == NULL ||
      load_state == NULL || save_state == NULL) {
    return CUBICRYPT_ERR_PARAMS;
  }

  ctx->initialized = false;

  if (params_invalid(params)) {
    return CUBICRYPT_ERR_PARAMS;
  }

  memcpy(ctx->primary_key, primary_key, CUBICRYPT_PRIMARY_KEY_BYTES);

  ctx->params.session_id_bits = params->session_id_bits;
  ctx->params.frame_iv_bits = params->frame_iv_bits;

  ctx->persistent_storage.load = load_state;
  ctx->persistent_storage.save = save_state;
  ctx->persistent_storage.user_data = storage_user_data;

  if (!load_state(&ctx->next_valid_session_state, storage_user_data)) {
    return CUBICRYPT_ERR_STORAGE;
  }

  cubicrypt_session_state safe_recovery_state;
  safe_recovery_state.id = ctx->next_valid_session_state.id + 1;
  safe_recovery_state.iv = 0;

  assert(ctx->persistent_storage.save != NULL);
  if (!save_state(safe_recovery_state, storage_user_data)) {
    return CUBICRYPT_ERR_STORAGE;
  }

  ctx->initialized = true;

  return CUBICRYPT_ERR_OK;
}

cubicrypt_err cubicrypt_out_new_session(cubicrypt_out_ctx* ctx,
                                        uint32_t session_id) {
  if (ctx == NULL || !ctx->initialized) {
    return CUBICRYPT_ERR_PARAMS;
  }

  if (session_id > max_u32(ctx->params.session_id_bits)) {
    return CUBICRYPT_ERR_PARAMS;
  }

  if (session_id <= ctx->next_valid_session_state.id) {
    return CUBICRYPT_ERR_PARAMS;  // TODO: This should be an auth error. Why no
                                  // test failure?
  }

  cubicrypt_session_state safe_recovery_state;
  safe_recovery_state.id = session_id + 1;
  safe_recovery_state.iv = 0;

  assert(ctx->persistent_storage.save != NULL);
  if (!ctx->persistent_storage.save(safe_recovery_state,
                                    ctx->persistent_storage.user_data)) {
    return CUBICRYPT_ERR_STORAGE;
  }

  ctx->next_valid_session_state.id = session_id;
  ctx->next_valid_session_state.iv = 0;

  return CUBICRYPT_ERR_OK;
}

static cubicrypt_err get_then_increment_session_state(cubicrypt_out_ctx* ctx,
                                                      uint32_t* session_id,
                                                      uint32_t* frame_iv) {
  *session_id = ctx->next_valid_session_state.id;
  *frame_iv = ctx->next_valid_session_state.iv;

  uint32_t frame_iv_mask = ~((uint32_t) 0) >> (32 - ctx->params.frame_iv_bits);

  if ((ctx->next_valid_session_state.iv = (*frame_iv + 1) & frame_iv_mask) ==
      0) {
    ctx->next_valid_session_state.id++;  // TODO: Overflow

    // TODO: Overflow, refactor
    cubicrypt_session_state safe_recovery_state;
    safe_recovery_state.id = ctx->next_valid_session_state.id + 1;
    safe_recovery_state.iv = 0;

    if (!ctx->persistent_storage.save(safe_recovery_state,
                                      ctx->persistent_storage.user_data)) {
      return CUBICRYPT_ERR_STORAGE;
    }
  }

  return CUBICRYPT_ERR_OK;
}

cubicrypt_err cubicrypt_out_encode(cubicrypt_out_ctx* ctx, uint32_t* session_id,
                                   uint32_t* frame_iv, bool encrypt,
                                   const void* aad, size_t aad_size,
                                   const void* body, size_t body_size,
                                   void* auth_tag, void* out_buf,
                                   const void** out) {
  if (ctx == NULL || !ctx->initialized) {
    return CUBICRYPT_ERR_PARAMS;
  }

  // TODO: If a subsequent function fails, this should not have incremented the
  // counter.
  cubicrypt_err err =
      get_then_increment_session_state(ctx, session_id, frame_iv);
  if (err != CUBICRYPT_ERR_OK) {
    return err;
  }

  uint8_t session_key[CUBICRYPT_SESSION_KEY_BYTES];
  bool crypto_ok =
      compute_session_key(ctx->primary_key, *session_id, session_key);
  if (!crypto_ok) {
    return CUBICRYPT_ERR_CRYPTO_LIB;
  }

  uint8_t padded_iv[CUBICRYPT_AES_GCM_IV_BYTES];
  compute_iv(*frame_iv, encrypt, padded_iv);

  if (encrypt) {
    crypto_ok =
        cubicrypt_aes_128_gcm_encrypt(session_key, padded_iv, aad, aad_size,
                                      body, body_size, out_buf, auth_tag);
  } else {
    cubicrypt_padded padded;
    pad_for_aad(&padded, aad, aad_size, body, body_size);
    crypto_ok = cubicrypt_aes_128_gmac_compute(session_key, padded_iv,
                                               &padded.iovecs, auth_tag);
  }

  memset(session_key, 0, sizeof(session_key));

  if (!crypto_ok) {
    return CUBICRYPT_ERR_CRYPTO_LIB;
  }

  if (out != NULL) *out = encrypt ? out_buf : body;

  return CUBICRYPT_ERR_OK;
}

cubicrypt_err cubicrypt_out_encode_copy(cubicrypt_out_ctx* ctx,
                                        uint32_t* session_id,
                                        uint32_t* frame_iv, bool encrypt,
                                        const void* aad, size_t aad_size,
                                        const void* body, size_t body_size,
                                        void* auth_tag, void* out_buf) {
  const void* out;
  cubicrypt_err err =
      cubicrypt_out_encode(ctx, session_id, frame_iv, encrypt, aad, aad_size,
                           body, body_size, auth_tag, out_buf, &out);
  if (err == CUBICRYPT_ERR_OK && out != out_buf) {
    memcpy(out_buf, out, body_size);
  }
  return err;
}

cubicrypt_err cubicrypt_out_auth_encrypt(cubicrypt_out_ctx* ctx,
                                         uint32_t* session_id,
                                         uint32_t* frame_iv, const void* aad,
                                         size_t aad_size, const void* body,
                                         size_t body_size, void* auth_tag,
                                         void* out_buf) {
  return cubicrypt_out_encode(ctx, session_id, frame_iv, true, aad, aad_size,
                              body, body_size, auth_tag, out_buf, NULL);
}

cubicrypt_err cubicrypt_out_auth_only(cubicrypt_out_ctx* ctx,
                                      uint32_t* session_id, uint32_t* frame_iv,
                                      const void* aad, size_t aad_size,
                                      const void* body, size_t body_size,
                                      void* auth_tag) {
  return cubicrypt_out_encode(ctx, session_id, frame_iv, false, aad, aad_size,
                              body, body_size, auth_tag, NULL, NULL);
}

cubicrypt_err cubicrypt_out_deinit(cubicrypt_out_ctx* ctx) {
  if (ctx == NULL || !ctx->initialized) {
    return CUBICRYPT_ERR_PARAMS;
  }

  if (!ctx->persistent_storage.save(ctx->next_valid_session_state,
                                    ctx->persistent_storage.user_data)) {
    return CUBICRYPT_ERR_STORAGE;
  }

  ctx->initialized = false;
  memset(ctx->primary_key, 0, sizeof(ctx->primary_key));

  return CUBICRYPT_ERR_OK;
}

cubicrypt_err cubicrypt_in_init(cubicrypt_in_ctx* ctx, const void* primary_key,
                                const cubicrypt_params* params,
                                cubicrypt_session_persistent_load_fn load_state,
                                cubicrypt_session_persistent_save_fn save_state,
                                void* storage_user_data) {
  if (ctx == NULL || primary_key == NULL || params == NULL ||
      load_state == NULL || save_state == NULL) {
    return CUBICRYPT_ERR_PARAMS;
  }

  ctx->initialized = false;

  if (params_invalid(params)) {
    return CUBICRYPT_ERR_PARAMS;
  }

  memcpy(ctx->primary_key, primary_key, CUBICRYPT_PRIMARY_KEY_BYTES);

  ctx->params.session_id_bits = params->session_id_bits;
  ctx->params.frame_iv_bits = params->frame_iv_bits;

  ctx->persistent_storage.load = load_state;
  ctx->persistent_storage.save = save_state;
  ctx->persistent_storage.user_data = storage_user_data;

  if (!load_state(&ctx->smallest_valid_session_state, storage_user_data)) {
    return CUBICRYPT_ERR_STORAGE;
  }

  cubicrypt_session_state safe_recovery_state;
  safe_recovery_state.id = ctx->smallest_valid_session_state.id + 1;
  safe_recovery_state.iv = 0;
  if (!save_state(safe_recovery_state, storage_user_data)) {
    return CUBICRYPT_ERR_STORAGE;
  }

#ifndef CUBICRYPT_NO_OUT_OF_ORDER
  ctx->ooo_window = 0;
#endif

  ctx->initialized = true;
  return CUBICRYPT_ERR_OK;
}

cubicrypt_err cubicrypt_in_decode(cubicrypt_in_ctx* ctx, uint32_t session_id,
                                  uint32_t frame_iv, bool is_encrypted,
                                  const void* aad, size_t aad_size,
                                  const void* body, size_t body_size,
                                  const void* auth_tag, void* out_buf,
                                  const void** out) {
  if (ctx == NULL || !ctx->initialized) {
    return CUBICRYPT_ERR_PARAMS;
  }

  if (session_id > max_u32(ctx->params.session_id_bits)) {
    return CUBICRYPT_ERR_PARAMS;
  }

  if (frame_iv > max_u32(ctx->params.frame_iv_bits)) {
    return CUBICRYPT_ERR_PARAMS;
  }

  if (body_size > 0 && (body == NULL || (is_encrypted && out_buf == NULL))) {
    return CUBICRYPT_ERR_PARAMS;
  }

  if (auth_tag == NULL) {
    return CUBICRYPT_ERR_PARAMS;
  }

#ifndef CUBICRYPT_NO_OUT_OF_ORDER
  bool was_ooo = false;
#endif

  if (session_id < ctx->smallest_valid_session_state.id) {
    return CUBICRYPT_ERR_AUTH;
  } else if (session_id == ctx->smallest_valid_session_state.id) {
    if (frame_iv < ctx->smallest_valid_session_state.iv) {
#ifndef CUBICRYPT_NO_OUT_OF_ORDER
      uint32_t gap = ctx->smallest_valid_session_state.iv - frame_iv - 1;
      if (gap < 1 || gap > CUBICRYPT_OUT_OF_ORDER_WINDOW_BITS ||
          (ctx->ooo_window & ((cubicrypt_ooo_window) 1u << (gap - 1))) == 0) {
        return CUBICRYPT_ERR_AUTH;
      }
      was_ooo = true;
#else
      return CUBICRYPT_ERR_AUTH;
#endif
    }
  }

  uint8_t session_key[CUBICRYPT_SESSION_KEY_BYTES];
  bool crypto_ok =
      compute_session_key(ctx->primary_key, session_id, session_key);
  if (!crypto_ok) {
    return CUBICRYPT_ERR_CRYPTO_LIB;
  }

  uint8_t padded_iv[CUBICRYPT_AES_GCM_IV_BYTES];
  compute_iv(frame_iv, is_encrypted, padded_iv);

  bool verify_ok;
  if (is_encrypted) {
    crypto_ok = cubicrypt_aes_128_gcm_decrypt(session_key, padded_iv, aad,
                                              aad_size, body, body_size,
                                              out_buf, auth_tag, &verify_ok);
  } else {
    cubicrypt_padded padded;
    pad_for_aad(&padded, aad, aad_size, body, body_size);
    crypto_ok = cubicrypt_aes_128_gmac_verify(
        session_key, padded_iv, &padded.iovecs, auth_tag, &verify_ok);
  }

  memset(session_key, 0, sizeof(session_key));

  if (!crypto_ok) {
    return CUBICRYPT_ERR_CRYPTO_LIB;
  }

  if (!verify_ok) {
    return CUBICRYPT_ERR_AUTH;
  }

  if (session_id > ctx->smallest_valid_session_state.id) {
    cubicrypt_session_state safe_recovery_state;
    safe_recovery_state.id = session_id + 1;
    safe_recovery_state.iv = 0;

    assert(ctx->persistent_storage.save != NULL);
    if (!ctx->persistent_storage.save(safe_recovery_state,
                                      ctx->persistent_storage.user_data)) {
      return CUBICRYPT_ERR_STORAGE;
    }

#ifndef CUBICRYPT_NO_OUT_OF_ORDER
    ctx->ooo_window = 0;
#endif

    ctx->smallest_valid_session_state.id = session_id;
#ifndef CUBICRYPT_NO_OUT_OF_ORDER
  } else if (frame_iv >= ctx->smallest_valid_session_state.iv) {
    uint32_t gap = frame_iv - ctx->smallest_valid_session_state.iv;
    if (gap >= CUBICRYPT_OUT_OF_ORDER_WINDOW_BITS) {
      ctx->ooo_window = ~(cubicrypt_ooo_window) 0;
    } else {
      cubicrypt_ooo_window gap_mask =
          (gap == 0)
              ? 0
              : ((cubicrypt_ooo_window) (~(cubicrypt_ooo_window) 0)) >>
                    (cubicrypt_ooo_window) (CUBICRYPT_OUT_OF_ORDER_WINDOW_BITS -
                                            gap);
      ctx->ooo_window = (ctx->ooo_window << (gap + 1)) | gap_mask;
    }
  } else {
    uint32_t gap = ctx->smallest_valid_session_state.iv - frame_iv - 1;
    ctx->ooo_window &= ~((cubicrypt_ooo_window) 1u << (gap - 1));
#endif
  }

#ifndef CUBICRYPT_NO_OUT_OF_ORDER
  if (!was_ooo) {
#else
  if (true) {
#endif
    ctx->smallest_valid_session_state.iv = frame_iv + 1;
  }

  if (out != NULL) *out = is_encrypted ? out_buf : body;

  return CUBICRYPT_ERR_OK;
}

cubicrypt_err cubicrypt_in_decode_copy(cubicrypt_in_ctx* ctx,
                                       uint32_t session_id, uint32_t frame_iv,
                                       bool is_encrypted, const void* aad,
                                       size_t aad_size, const void* body,
                                       size_t body_size, const void* auth_tag,
                                       void* out_buf) {
  const void* out;
  cubicrypt_err err =
      cubicrypt_in_decode(ctx, session_id, frame_iv, is_encrypted, aad,
                          aad_size, body, body_size, auth_tag, out_buf, &out);
  if (err == CUBICRYPT_ERR_OK && out != out_buf) {
    memcpy(out_buf, out, body_size);
  }
  return err;
}

cubicrypt_err cubicrypt_in_verify_decrypt(cubicrypt_in_ctx* ctx,
                                          uint32_t session_id,
                                          uint32_t frame_iv, const void* aad,
                                          size_t aad_size, const void* body,
                                          size_t body_size,
                                          const void* auth_tag, void* out) {
  return cubicrypt_in_decode(ctx, session_id, frame_iv, true, aad, aad_size,
                             body, body_size, auth_tag, out, NULL);
}

cubicrypt_err cubicrypt_in_verify_only(cubicrypt_in_ctx* ctx,
                                       uint32_t session_id, uint32_t frame_iv,
                                       const void* aad, size_t aad_size,
                                       const void* body, size_t body_size,
                                       const void* auth_tag) {
  return cubicrypt_in_decode(ctx, session_id, frame_iv, false, aad, aad_size,
                             body, body_size, auth_tag, NULL, NULL);
}

cubicrypt_err cubicrypt_in_deinit(cubicrypt_in_ctx* ctx) {
  if (ctx == NULL || !ctx->initialized) {
    return CUBICRYPT_ERR_PARAMS;
  }

  if (!ctx->persistent_storage.save(ctx->smallest_valid_session_state,
                                    ctx->persistent_storage.user_data)) {
    return CUBICRYPT_ERR_STORAGE;
  }

  ctx->initialized = false;
  memset(ctx->primary_key, 0, sizeof(ctx->primary_key));

  return CUBICRYPT_ERR_OK;
}
