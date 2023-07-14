#ifndef __CUBICRYPT_H__
#define __CUBICRYPT_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef CUBICRYPT_NO_CONFIG_H
#  include <cubicrypt/config.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

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
/** The sending context has run out of session identifiers. */
#define CUBICRYPT_ERR_SESSIONS_EXHAUSTED ((cubicrypt_err) 0x75)

/** The size of the context ID, in bytes. */
#define CUBICRYPT_CONTEXT_ID_BYTES 8

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
   * Identifies the context in which the primary key is being used.
   *
   * While this allows using the same primary key in multiple contexts, each
   * primary key should be used in a small number of contexts only. For example,
   * the same primary key may be used for both directions of a duplex channel,
   * provided that different context IDs are used for each direction.
   *
   * This field has a size of 64 bits. For example, a duplex channel may use the
   * context identifiers "gnd->sat" and "sat->gnd" for the two directions
   * between a ground station and a satellite. Do not assume that it is safe to
   * use the same primary key in a large number of contexts, let alone in 2^64
   * contexts.
   *
   * Instead, consider using the key exchange functions further below to
   * generate new primary keys for new contexts.
   */
  uint8_t context_id[CUBICRYPT_CONTEXT_ID_BYTES];

  /**
   * Identifies the epoch in which the primary key is being used.
   *
   * The epoch field functions very differently from the session ID and frame
   * IV. While the session ID and frame IV are managed automatically by
   * Cubicrypt, the epoch field is managed by the application. Mismanagement of
   * the epoch field can lead to a total loss of security and functionality.
   *
   * Cubicrypt does not interpret this field. Applications may use it to begin
   * a new sequence of session IDs and frame IVs while reusing the same primary
   * key and context ID. However, such state transitions are not managed by
   * core Cubicrypt functions, and must be implemented by the application
   * itself.
   */
  uint32_t epoch;

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

/**
 * Returns the persistent state for a new, to-be-initialized Cubicrypt context.
 *
 * This function must not be used for existing contexts. It should only be used
 * to initialize persistent storage for an entirely new context.
 */
cubicrypt_session_state cubicrypt_initial_persistent_state(void);

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
 * Retrieves the current and the maximum session ID and frame IV.
 *
 * Each sending context has a finite life span, after which it becomes
 * inoperable. This is due to the limited number of session IDs, as well as the
 * limited number of frame IVs per session.
 *
 * Applications can use this function to estimate the remaining life span of the
 * context in order to determine when a new context should be created.
 *
 * A sending context becomes inoperable when it exceeds the maximum session ID.
 * In that case, this function returns CUBICRYPT_ERR_SESSIONS_EXHAUSTED.
 *
 * If this function returns CUBICRYPT_ERR_OK, session_id will be set to the
 * current session ID and max_session_id will be set to the maximum session ID.
 * The current session ID is always at least one and at most the maximum session
 * ID.
 *
 * The frame IV is incremented within each session and generally insignificant
 * for estimating the context's remaining life span. It is provided mainly for
 * debugging and statistical purposes.
 *
 * Each of the four pointers may be `NULL`.
 *
 * @param ctx The `cubicrypt_out_ctx`.
 * @param session_id Receives the current session ID.
 * @param frame_iv Receives the current frame IV.
 * @param max_session_id Receives the maximum session ID.
 * @param max_session_id Receives the maximum frame IV.
 * @return Cubicrypt error code
 */
cubicrypt_err cubicrypt_out_get_session_status(cubicrypt_out_ctx* ctx,
                                               uint32_t* session_id,
                                               uint32_t* frame_iv,
                                               uint32_t* max_session_id,
                                               uint32_t* max_frame_iv);

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

#ifndef CUBICRYPT_NO_OUT_OF_ORDER
#  ifdef CUBICRYPT_OUT_OF_ORDER_LARGE_WINDOW
#    define __CUBICRYPT_OUT_OF_ORDER_WINDOW_INT_T uint64_t
#  elif defined(CUBICRYPT_OUT_OF_ORDER_SMALL_WINDOW)
#    define __CUBICRYPT_OUT_OF_ORDER_WINDOW_INT_T uint16_t
#  else
#    define __CUBICRYPT_OUT_OF_ORDER_WINDOW_INT_T uint32_t
#  endif

/**
 * The unsigned integer type that internally represent the out-of-order window.
 */
typedef __CUBICRYPT_OUT_OF_ORDER_WINDOW_INT_T cubicrypt_ooo_window;

#  undef __CUBICRYPT_OUT_OF_ORDER_WINDOW_INT_T

/**
 * The number of bits in the out-of-order window.
 */
#  define CUBICRYPT_OUT_OF_ORDER_WINDOW_BITS (sizeof(cubicrypt_ooo_window) * 8)
#endif

typedef struct {
  bool initialized;
  uint8_t primary_key[CUBICRYPT_PRIMARY_KEY_BYTES];
  cubicrypt_params params;
  cubicrypt_session_state smallest_valid_session_state;
  cubicrypt_session_persistent_storage persistent_storage;

#ifndef CUBICRYPT_NO_OUT_OF_ORDER
  cubicrypt_ooo_window ooo_window;
#endif
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
 * Retrieves the current and the maximum session ID and frame IV.
 *
 * Each receiving context has a finite life span, after which it becomes
 * inoperable. This is due to the limited number of session IDs, as well as the
 * limited number of frame IVs per session.
 *
 * Applications can use this function to estimate the remaining life span of the
 * context in order to determine when a new context should be created.
 *
 * A receiving context becomes inoperable when it exceeds the maximum session
 * ID. In that case, this function returns CUBICRYPT_ERR_SESSIONS_EXHAUSTED.
 *
 * If this function returns CUBICRYPT_ERR_OK, session_id will be set to the
 * current session ID and max_session_id will be set to the maximum session ID.
 * The current session ID is always at least one and at most the maximum session
 * ID.
 *
 * The frame IV is incremented within each session and generally insignificant
 * for estimating the context's remaining life span. It is provided mainly for
 * debugging and statistical purposes.
 *
 * Each of the four pointers may be `NULL`.
 *
 * @param ctx The `cubicrypt_in_ctx`.
 * @param session_id Receives the current session ID.
 * @param frame_iv Receives the current frame IV.
 * @param max_session_id Receives the maximum session ID.
 * @param max_session_id Receives the maximum frame IV.
 * @return Cubicrypt error code
 */
cubicrypt_err cubicrypt_in_get_session_status(cubicrypt_in_ctx* ctx,
                                              uint32_t* session_id,
                                              uint32_t* frame_iv,
                                              uint32_t* max_session_id,
                                              uint32_t* max_frame_iv);

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

#ifndef CUBICRYPT_NO_KEY_EXCHANGE

/**
 * The size of a public key that is used for a key exchange, in bytes.
 */
#  define CUBICRYPT_KX_PUBLIC_KEY_BYTES 32

/**
 * The size of a private key that is used for a key exchange, in bytes.
 */
#  define CUBICRYPT_KX_PRIVATE_KEY_BYTES 32

/**
 * Generates a new key pair for use with a key exchange operation.
 *
 * The life span of Cubicrypt contexts is finite by design. The primary key can
 * only be used to derive a finite number of session keys, and each session key
 * can only be used for a finite number of frames. While this may be acceptable
 * for many applications, it may be desirable to be able to exchange new primary
 * keys with the other endpoint in order to create entirely new Cubicrypt
 * contexts.
 *
 * This function can be used before a key exchange operation to generate a new
 * ephemeral key pair. It can also be used to generate a static key pair that
 * can be used for multiple key exchange operations. While ephemeral key pairs
 * are often preferred for security reasons, it may be desirable to assign a
 * static key pair to a particular endpoint (e.g., a satellite).
 *
 * This function fails if and only if any of its arguments are NULL or if the
 * key pair generation operation fails due to a failure of the underlying crypto
 * library.
 *
 * @param[out] public_key The generated public key will be written to this
 *                        location as a sequence of
 *                        CUBICRYPT_KX_PUBLIC_KEY_BYTES bytes.
 * @param[out] private_key The generated private key will be written to this
 *                         location as a sequence of
 *                         CUBICRYPT_KX_PRIVATE_KEY_BYTES bytes.
 * @return `true` if the key pair generation operation succeeded, `false`
 *         otherwise.
 */
bool cubicrypt_kx_generate_keypair(void* public_key, void* private_key);

/**
 * Derives a primary key by performing the key exchange operation with the given
 * public key and the given private key.
 *
 * Forward secrecy is provided only if both keys are ephemeral. At least one of
 * the keys must be ephemeral, otherwise, the derived primary key will be
 * static. In other words, at most one of the given keys must be static.
 *
 * This function fails if and only if any of its arguments are NULL or if the
 * key exchange operation fails, either due to an invalid input or due to a
 * failure of the underlying crypto library.
 *
 * @param[out] new_primary_key The derived primary key will be written to this
 *                             location as a sequence of
 *                             CUBICRYPT_PRIMARY_KEY_BYTES bytes.
 * @param[in] other_public_key The public key of the other endpoint, which must
 *                             be a sequence of CUBICRYPT_KX_PUBLIC_KEY_BYTES.
 * @param[in] own_private_key The private key of the local endpoint, which must
 *                            be a sequence of CUBICRYPT_KX_PRIVATE_KEY_BYTES.
 * @return `true` if the key exchange operation succeeded, `false` otherwise.
 */
bool cubicrypt_kx_derive_primary_key(void* new_primary_key,
                                     const void* other_public_key,
                                     const void* own_private_key);

/**
 * Generates a new primary key for one or more Cubicrypt contexts by generating
 * a new key pair and performing the key exchange operation with the given
 * public key and the newly generated key pair.
 *
 * This function is particularly useful when one endpoint uses a static key pair
 * for computing new primary keys. The endpoint that does not use a static key
 * pair can use this function to generate a new (ephermal) key pair and perform
 * the key exchange operation with the other endpoint's (static) public key. The
 * generated public key must then be transmitted to the other endpoint so that
 * the respective application can derive the same primary key from its (static)
 * private key and the received public key.
 *
 * Otherwise, forward secrecy is provided if and only if the other endpoint
 * uses an ephemeral key pair, that is, if and only if `other_public_key` is
 * ephemeral.
 *
 * This function fails if and only if any of its arguments are NULL or if the
 * key exchange operation fails, either due to an invalid input or due to a
 * failure of the underlying crypto library.
 *
 * @param[out] new_primary_key The derived primary key will be written to this
 *                             location as a sequence of
 *                             CUBICRYPT_PRIMARY_KEY_BYTES bytes.
 * @param[in] other_public_key The public key of the other endpoint, which must
 *                             be a sequence of CUBICRYPT_KX_PUBLIC_KEY_BYTES
 *                             bytes.
 * @param[out] ephemeral_public_key The generated ephemeral public key will be
 *                                  written to this location as a sequence of
 *                                  CUBICRYPT_KX_PUBLIC_KEY_BYTES bytes.
 * @return `true` if the operation succeeded, `false` otherwise.
 */
bool cubicrypt_kx_generate_primary_key(void* new_primary_key,
                                       const void* other_public_key,
                                       void* ephemeral_public_key);

#endif

#ifdef __cplusplus
}
#endif

#endif  // __CUBICRYPT_H__
