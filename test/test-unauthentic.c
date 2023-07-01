#include "common.h"

#include <string.h>

static void setup(
    cubicrypt_out_ctx* sender, cubicrypt_session_state* sender_persistent_state,
    cubicrypt_in_ctx* receiver,
    cubicrypt_session_state* receiver_persistent_state,
    cubicrypt_in_ctx* receiver_w_diff_key,
    cubicrypt_session_state* receiver_w_diff_key_persistent_state,
    cubicrypt_in_ctx* receiver_w_diff_context_id,
    cubicrypt_session_state* receiver_w_diff_context_id_persistent_state,
    cubicrypt_in_ctx* receiver_w_diff_epoch,
    cubicrypt_session_state* receiver_w_diff_epoch_persistent_state);

static void test_unauthentic(cubicrypt_out_ctx* sender,
                             cubicrypt_in_ctx* receiver,
                             cubicrypt_in_ctx* receiver_w_diff_key,
                             cubicrypt_in_ctx* receiver_w_diff_context_id,
                             cubicrypt_in_ctx* receiver_w_diff_epoch);

CUBICRYPT_TEST_MAIN(unauthentic) {
  cubicrypt_out_ctx sender;
  cubicrypt_session_state sender_persistent_state =
      cubicrypt_initial_persistent_state();
  cubicrypt_in_ctx receiver;
  cubicrypt_session_state receiver_persistent_state =
      cubicrypt_initial_persistent_state();
  cubicrypt_in_ctx receiver_w_diff_key;
  cubicrypt_session_state receiver_w_diff_key_persistent_state =
      cubicrypt_initial_persistent_state();
  cubicrypt_in_ctx receiver_w_diff_context_id;
  cubicrypt_session_state receiver_w_diff_context_id_persistent_state =
      cubicrypt_initial_persistent_state();
  cubicrypt_in_ctx receiver_w_diff_epoch;
  cubicrypt_session_state receiver_w_diff_epoch_persistent_state =
      cubicrypt_initial_persistent_state();

  // Prepare the individual contexts.
  setup(&sender, &sender_persistent_state, &receiver,
        &receiver_persistent_state, &receiver_w_diff_key,
        &receiver_w_diff_key_persistent_state, &receiver_w_diff_context_id,
        &receiver_w_diff_context_id_persistent_state, &receiver_w_diff_epoch,
        &receiver_w_diff_epoch_persistent_state);

  // Run the actual test multiple times with different session IDs.
  for (unsigned int i = 2; i <= 1000; i++) {
    test_unauthentic(&sender, &receiver, &receiver_w_diff_key,
                     &receiver_w_diff_context_id, &receiver_w_diff_epoch);
    assert_ok(cubicrypt_out_new_session(&sender, i));
  }
}

static void setup(
    cubicrypt_out_ctx* sender, cubicrypt_session_state* sender_persistent_state,
    cubicrypt_in_ctx* receiver,
    cubicrypt_session_state* receiver_persistent_state,
    cubicrypt_in_ctx* receiver_w_diff_key,
    cubicrypt_session_state* receiver_w_diff_key_persistent_state,
    cubicrypt_in_ctx* receiver_w_diff_context_id,
    cubicrypt_session_state* receiver_w_diff_context_id_persistent_state,
    cubicrypt_in_ctx* receiver_w_diff_epoch,
    cubicrypt_session_state* receiver_w_diff_epoch_persistent_state) {
  assert_ok(cubicrypt_out_init(sender, test_primary_key, &default_params,
                               load_session_state, save_session_state,
                               sender_persistent_state));

  assert_ok(cubicrypt_in_init(receiver, test_primary_key, &default_params,
                              load_session_state, save_session_state,
                              receiver_persistent_state));

  // Introduce a single-bit error into a copy of the primary key.
  uint8_t diff_primary_key[sizeof(test_primary_key)];
  memcpy(diff_primary_key, test_primary_key, sizeof(test_primary_key));
  diff_primary_key[0] ^= 1;

  assert_ok(cubicrypt_in_init(receiver_w_diff_key, diff_primary_key,
                              &default_params, load_session_state,
                              save_session_state,
                              receiver_w_diff_key_persistent_state));

  // Introduce a single-bit change into a copy of the context ID.
  cubicrypt_params diff_context_id_params = default_params;
  diff_context_id_params.context_id[3] ^= 1;

  assert_ok(cubicrypt_in_init(receiver_w_diff_context_id, test_primary_key,
                              &diff_context_id_params, load_session_state,
                              save_session_state,
                              receiver_w_diff_context_id_persistent_state));

  // Introduce a single-bit change into a copy of the epoch.
  cubicrypt_params diff_epoch_params = default_params;
  diff_epoch_params.epoch ^= 0x0155u;

  assert_ok(cubicrypt_in_init(receiver_w_diff_epoch, test_primary_key,
                              &diff_epoch_params, load_session_state,
                              save_session_state,
                              receiver_w_diff_epoch_persistent_state));
}

static void test_unauthentic(cubicrypt_out_ctx* sender,
                             cubicrypt_in_ctx* receiver,
                             cubicrypt_in_ctx* receiver_w_diff_key,
                             cubicrypt_in_ctx* receiver_w_diff_context_id,
                             cubicrypt_in_ctx* receiver_w_diff_epoch) {
  bool encrypted = false;
  do {
    uint32_t session_id;
    uint32_t frame_iv;
    char aad[] = "something";
    size_t aad_size = strlen(aad);
    const char* message = "Hello world";
    size_t message_size = strlen(message);
    uint8_t auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
    uint8_t enc_message[64];
    char plaintext[64];

    // Regular encoded message.
    assert_ok(cubicrypt_out_encode_copy(sender, &session_id, &frame_iv,
                                        encrypted, aad, aad_size, message,
                                        message_size, auth_tag, enc_message));

    // Incorrect "encrypted" flag.
    assert_eq(CUBICRYPT_ERR_AUTH,
              cubicrypt_in_decode_copy(receiver, session_id, frame_iv,
                                       !encrypted, aad, aad_size, enc_message,
                                       message_size, auth_tag, plaintext));

    // Valid but incorrect session ID.
    assert_eq(CUBICRYPT_ERR_AUTH,
              cubicrypt_in_decode_copy(receiver, session_id + 1, frame_iv,
                                       encrypted, aad, aad_size, enc_message,
                                       message_size, auth_tag, plaintext));

    // Valid but incorrect frame IV.
    assert_eq(CUBICRYPT_ERR_AUTH,
              cubicrypt_in_decode_copy(receiver, session_id, frame_iv + 1,
                                       encrypted, aad, aad_size, enc_message,
                                       message_size, auth_tag, plaintext));

    // Single-bit error in the AAD.
    aad[0] ^= 1;
    assert_eq(CUBICRYPT_ERR_AUTH,
              cubicrypt_in_decode_copy(receiver, session_id, frame_iv,
                                       encrypted, aad, aad_size, enc_message,
                                       message_size, auth_tag, plaintext));
    aad[0] ^= 1;

    // Single-bit error in the encrypted message.
    enc_message[0] ^= 1;
    assert_eq(CUBICRYPT_ERR_AUTH,
              cubicrypt_in_decode_copy(receiver, session_id, frame_iv,
                                       encrypted, aad, aad_size, enc_message,
                                       message_size, auth_tag, plaintext));
    enc_message[0] ^= 1;

    // Single-bit error in the authentication tag.
    auth_tag[0] ^= 1;
    assert_eq(CUBICRYPT_ERR_AUTH,
              cubicrypt_in_decode_copy(receiver, session_id, frame_iv,
                                       encrypted, aad, aad_size, enc_message,
                                       message_size, auth_tag, plaintext));
    auth_tag[0] ^= 1;

    // Incorrect message length.
    assert_eq(CUBICRYPT_ERR_AUTH,
              cubicrypt_in_decode_copy(receiver, session_id, frame_iv,
                                       encrypted, aad, aad_size, enc_message,
                                       message_size + 1, auth_tag, plaintext));

    // Incorrect primary key.
    assert_eq(CUBICRYPT_ERR_AUTH,
              cubicrypt_in_decode_copy(
                  receiver_w_diff_key, session_id, frame_iv, encrypted, aad,
                  aad_size, enc_message, message_size, auth_tag, plaintext));

    // Incorrect context ID.
    assert_eq(CUBICRYPT_ERR_AUTH,
              cubicrypt_in_decode_copy(receiver_w_diff_context_id, session_id,
                                       frame_iv, encrypted, aad, aad_size,
                                       enc_message, message_size, auth_tag,
                                       plaintext));

    // Incorrect epoch.
    assert_eq(CUBICRYPT_ERR_AUTH,
              cubicrypt_in_decode_copy(
                  receiver_w_diff_epoch, session_id, frame_iv, encrypted, aad,
                  aad_size, enc_message, message_size, auth_tag, plaintext));

    // Failed verifications should not update the session ID / frame IV, so the
    // receiver should still decode the original message correctly.
    assert_ok(cubicrypt_in_decode_copy(receiver, session_id, frame_iv,
                                       encrypted, aad, aad_size, enc_message,
                                       message_size, auth_tag, plaintext));
  } while ((encrypted = !encrypted));
}
