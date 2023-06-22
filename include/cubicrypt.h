#ifndef __CUBICRYPT_H__
#define __CUBICRYPT_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Cubicrypt functions have this return type. All codes other than
 * `CUBICRYPT_ERR_OK` indicate errors.
 *
 * Regardless of the size of the error type, which is selected by the compiler,
 * all error codes fit into the lower 7 bits. On most architectures, it is,
 * therefore, safe to cast this type to arbitrary integer types, both signed and
 * unsigned.
 */
typedef uint_fast8_t cubicrypt_err;

/** No error occurred. */
#define CUBICRYPT_ERR_OK ((cubicrypt_err) 0x00)
/** At least one parameter was passed incorrectly. */
#define CUBICRYPT_ERR_PARAMS ((cubicrypt_err) 0x71)
/** The persistent storage failed. */
#define CUBICRYPT_ERR_STORAGE ((cubicrypt_err) 0x72)
/** The crypto library failed, e.g., due to memory allocation failure or
    hardware acceleration timeouts. */
#define CUBICRYPT_ERR_CRYPTO_LIB ((cubicrypt_err) 0x73)
/** A frame could not be decoded due to an authentication failure. */
#define CUBICRYPT_ERR_AUTH ((cubicrypt_err) 0x74)

/** The minimum number of bits that session IDs must consist of. */
#define CUBICRYPT_MIN_SESSION_ID_BITS 16

/** The maximum number of bits that session IDs can consist of. */
#define CUBICRYPT_MAX_SESSION_ID_BITS 32

/** The minimum number of bits that frame IVs must consist of. */
#define CUBICRYPT_MIN_FRAME_IV_BITS 8

/** The maximum number of bits that frame IVs can consist of. */
#define CUBICRYPT_MAX_FRAME_IV_BITS 32

/** The size of the primary pre-shared key, in bytes. */
#define CUBICRYPT_PRIMARY_KEY_BYTES 32

/** The size of automatically derived session keys, in bytes. */
#define CUBICRYPT_SESSION_KEY_BYTES 16

/** The size of the initialization vector, in bytes. */
#define CUBICRYPT_AES_GCM_IV_BYTES 12

/** The size of the per-frame authentication tag, in bytes. */
#define CUBICRYPT_AES_GCM_AUTH_TAG_BYTES 8

/**
 * User-defined parameters for a Cubicrypt context.
 */
typedef struct {
  /**
   * The number of bits in a session identifier.
   *
   * Must be at least CUBICRYPT_MIN_SESSION_ID_BITS and at most
   * CUBICRYPT_MAX_SESSION_ID_BITS.
   * */
  uint8_t session_id_bits;

  /**
   * The number of bits in a frame counter.
   *
   * Must be at least CUBICRYPT_MIN_FRAME_IV_BITS and at most
   * CUBICRYPT_MAX_FRAME_IV_BITS.
   */
  uint8_t frame_iv_bits;
} cubicrypt_params;

/**
 * This data structure represents the entirety of the persistent state of a
 * Cubicrypt context. It always consists of 64 bits, however, depending on the
 * parameters, some of these bits may never be set.
 *
 * User-defined storage callbacks should not interpret the meaning of these
 * fields. The two 32-bit unsigned integers should be stored as such or, if the
 * storage will only ever be accessed from a compatible processor architecture,
 * user code may treat it as entirely opaque by statically asserting that
 * sizeof(cubicrypt_session_state) == 8 and then casting the data structure to a
 * char[8].
 */
typedef struct {
  /** Session ID.*/
  uint32_t id;
  /** Frame counter. */
  uint32_t iv;
} cubicrypt_session_state;

// TODO: consider using a uint64_t instead of cubicrypt_session_state below

/*
 * This is the type of a user-defined function that is used to load persistent
 * state from a user-supplied storage medium.
 *
 * The function should return true if the state was successfully loaded, and
 * false otherwise.
 */
typedef bool (*cubicrypt_session_persistent_load_fn)(
    cubicrypt_session_state* state, void* user_data);

/**
 * This is the type of a user-defined function that is used to save persistent
 * state to a user-supplied storage medium.
 *
 * The function should return true if the state was successfully saved, and
 * false otherwise. It is crucial for the security and reliability of the
 * Cubicrypt context that the persistent state is stored properly. Users are
 * encouraged to implement sufficient redundancy, error detection, and error
 * correction as necessary for the underlying storage medium.
 */
typedef bool (*cubicrypt_session_persistent_save_fn)(
    cubicrypt_session_state state, void* user_data);

typedef struct {
  void* user_data;
  cubicrypt_session_persistent_load_fn load;
  cubicrypt_session_persistent_save_fn save;
} cubicrypt_session_persistent_storage;

typedef struct {
  bool initialized;
  uint8_t primary_key[CUBICRYPT_PRIMARY_KEY_BYTES];
  cubicrypt_params params;
  cubicrypt_session_state next_valid_session_state;
  cubicrypt_session_persistent_storage persistent_storage;
} cubicrypt_out_ctx;

/**
 * Initializes a context to be used for encoding secure transmissions.
 *
 * The initialized context is not thread-safe. It is up to the application to
 * ensure that the same context is only accessed from a single thread at a time.
 *
 * @param ctx The `cubicrypt_out_ctx` to initialize.
 * @param primary_key The primary key that is used to derive session keys.
 * @param params Shared parameters. These will be copied and may be deallocated
 *               by the caller after this function returns.
 * @param load_state A function that can reliably load a
 * `cubicrypt_session_state` structure from persistent storage.
 * @param save_state A function that can reliably save a
 * `cubicrypt_session_state` structure to persistent storage.
 * @param storage_user_data An abitrary pointer that is passed through to
 *                          `load_state` and `save_state`.
 * @return Cubicrypt error code
 */
cubicrypt_err cubicrypt_out_init(
    cubicrypt_out_ctx* ctx, const void* primary_key,
    const cubicrypt_params* params,
    cubicrypt_session_persistent_load_fn load_state,
    cubicrypt_session_persistent_save_fn save_state, void* storage_user_data);

/**
 * Begins a new session with the given session ID.
 *
 * If the receiving side never malfunctions and always maintains its local state
 * without error, both in memory and on persistent storage, then calling this
 * function is not needed. However, if the receiving side might have crashed
 * since the last successful operation, it might have been forced to skip one or
 * more session IDs. In this case, waiting for the sending side to catch up with
 * the receiving side might take a long time. To avoid this, the sending side
 * can be instructed to skip ahead to a new session ID.
 *
 * @param ctx The `cubicrypt_out_ctx`.
 * @param session_id The new session ID.
 * @return Cubicrypt error code
 */
cubicrypt_err cubicrypt_out_new_session(cubicrypt_out_ctx* ctx,
                                        uint32_t session_id);

/**
 * Encodes a frame to be sent as a secure transmission.
 *
 * This function produces a session ID, a frame IV, an authentication tag,
 * and optionally a ciphertext.
 *
 * @param ctx The `cubicrypt_out_ctx`.
 * @param session_id The produced session ID.
 * @param frame_iv The produced frame IV.
 * @param encrypt If `false`, the message will not be encrypted, however, an
 *                authentication tag will still be computed. Otherwise, the
 *                message will be encrypted and an authentication tag will be
 *                computed.
 * @param body The message that is to be encoded.
 * @param body_size The size of the message that is to be encoded, in bytes.
 * @param auth_tag The produced authentication tag will be written to this
 *                 pointer. The caller is responsible for ensuring that enough
 *                 memory is available at the given pointer to hold the
 *                 authentication tag.
 * @param out If `encrypt` is `false`, the message will be copied to the memory
 *            pointed to by `out`. Otherwise, the message will be encrypted and
 *            the resulting ciphertext will be written to the memory pointed to
 *            by `out`.
 * @return Cubicrypt error code
 */
cubicrypt_err cubicrypt_out_encode(cubicrypt_out_ctx* ctx, uint32_t* session_id,
                                   uint32_t* frame_iv, bool encrypt,
                                   const void* aad, size_t aad_size,
                                   const void* body, size_t body_size,
                                   void* auth_tag, void* out_buf,
                                   const void** out);

cubicrypt_err cubicrypt_out_encode_copy(cubicrypt_out_ctx* ctx,
                                        uint32_t* session_id,
                                        uint32_t* frame_iv, bool encrypt,
                                        const void* aad, size_t aad_size,
                                        const void* body, size_t body_size,
                                        void* auth_tag, void* out_buf);

cubicrypt_err cubicrypt_out_auth_encrypt(cubicrypt_out_ctx* ctx,
                                         uint32_t* session_id,
                                         uint32_t* frame_iv, const void* aad,
                                         size_t aad_size, const void* body,
                                         size_t body_size, void* auth_tag,
                                         void* out);

cubicrypt_err cubicrypt_out_auth_only(cubicrypt_out_ctx* ctx,
                                      uint32_t* session_id, uint32_t* frame_iv,
                                      const void* aad, size_t aad_size,
                                      const void* body, size_t body_size,
                                      void* auth_tag);

/**
 * Deinitializes a context that was used to encode secure transmissions.
 *
 * This function erases security-critical data from memory.
 *
 * If this function is not called, e.g., because of a system crash, the system
 * will remain functional and secure, however, it will not be able to reuse the
 * current session ID and a new session will be started during the next
 * initialization.
 *
 * If the system is not in a stable state, it is generally safer to avoid
 * calling this function because it modifies data stored on persistent storage.
 * As a rule of thumb, this function should only be called as part of a planned
 * and expected shutdown procedure.
 *
 * @param ctx The `cubicrypt_out_ctx` to deinitialize.
 * @return Cubicrypt error code
 */
cubicrypt_err cubicrypt_out_deinit(cubicrypt_out_ctx* ctx);

typedef struct {
  bool initialized;
  uint8_t primary_key[CUBICRYPT_PRIMARY_KEY_BYTES];
  cubicrypt_params params;
  cubicrypt_session_state smallest_valid_session_state;
  cubicrypt_session_persistent_storage persistent_storage;
} cubicrypt_in_ctx;

/**
 * Initializes a context to be used for decoding secure transmissions.
 *
 * The initialized context is not thread-safe. It is up to the application to
 * ensure that the same context is only accessed from a single thread at a time.
 *
 * @param ctx The `cubicrypt_in_ctx` to initialize.
 * @param primary_key The primary key that is used to derive session keys.
 * @param params Shared parameters. These will be copied and may be deallocated
 *               by the caller after this function returns.
 * @param load_state A function that can reliably load a
 * `cubicrypt_session_state` structure from persistent storage.
 * @param save_state A function that can reliably save a
 * `cubicrypt_session_state` structure to persistent storage.
 * @param storage_user_data An abitrary pointer that is passed through to
 *                          `load_state` and `save_state`.
 * @return Cubicrypt error code
 */
cubicrypt_err cubicrypt_in_init(cubicrypt_in_ctx* ctx, const void* primary_key,
                                const cubicrypt_params* params,
                                cubicrypt_session_persistent_load_fn load_state,
                                cubicrypt_session_persistent_save_fn save_state,
                                void* storage_user_data);

/**
 * Decodes a frame that was received as a secure transmission.
 *
 * This function consumes a session ID, a frame IV, an authentication tag,
 * and either the plaintext or ciphertext. If the frame is authentic, the
 * plaintext will be provided, otherwise, the function fails.
 *
 * @param ctx The `cubicrypt_in_ctx`.
 * @param session_id The received session ID.
 * @param frame_iv The received frame IV.
 * @param is_encrypted If `false`, the `body` is assumed to be the plaintext,
 *                     and the authenticity of the message will be verified
 *                     using the authentication tag. Otherwise, the `body` will
 *                     additionally be decrypted and the result will be stored
 *                     in `out`.
 * @param body The received plaintext or ciphertext, depending on the value of
 *             `is_encrypted`.
 * @param body_size The size of the plaintext/ciphertext, in bytes.
 * @param auth_tag The received authentication tag.
 * @param out If `is_encrypted` is `false`, the plaintext will be copied to the
 *            memory pointed to by `out`. Otherwise, the message will be
 *            decrypted and the resulting plaintext will be written to the
 *            memory pointed to by `out`.
 * @return Cubicrypt error code
 */
cubicrypt_err cubicrypt_in_decode(cubicrypt_in_ctx* ctx, uint32_t session_id,
                                  uint32_t frame_iv, bool is_encrypted,
                                  const void* aad, size_t aad_size,
                                  const void* body, size_t body_size,
                                  const void* auth_tag, void* out_buf,
                                  const void** out);

cubicrypt_err cubicrypt_in_decode_copy(cubicrypt_in_ctx* ctx,
                                       uint32_t session_id, uint32_t frame_iv,
                                       bool is_encrypted, const void* aad,
                                       size_t aad_size, const void* body,
                                       size_t body_size, const void* auth_tag,
                                       void* out_buf);

cubicrypt_err cubicrypt_in_verify_decrypt(cubicrypt_in_ctx* ctx,
                                          uint32_t session_id,
                                          uint32_t frame_iv, const void* aad,
                                          size_t aad_size, const void* body,
                                          size_t body_size,
                                          const void* auth_tag, void* out);

cubicrypt_err cubicrypt_in_verify_only(cubicrypt_in_ctx* ctx,
                                       uint32_t session_id, uint32_t frame_iv,
                                       const void* aad, size_t aad_size,
                                       const void* body, size_t body_size,
                                       const void* auth_tag);

/**
 * Deinitializes a context that was used to decode secure transmissions.
 *
 * This function erases security-critical data from memory.
 *
 * If this function is not called, e.g., because of a system crash, the system
 * will remain functional and secure, however, it will not be able to receive
 * frames that use the current session ID. Frames will only be recognized as
 * authentic when a new session has begun.
 *
 * If the system is not in a stable state, it is generally safer to avoid
 * calling this function because it modifies data stored in persistent memory.
 * As a rule of thumb, this function should only be called as part of a planned
 * and expected shutdown procedure.
 *
 * @param ctx The `cubicrypt_in_ctx` to deinitialize.
 * @return Cubicrypt error code
 */
cubicrypt_err cubicrypt_in_deinit(cubicrypt_in_ctx* ctx);

#endif  // __CUBICRYPT_H__
