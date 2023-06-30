#include "common.h"

#include <string.h>

static cubicrypt_err send_and_receive(cubicrypt_out_ctx* sender,
                                      cubicrypt_in_ctx* receiver) {
  const char* aad = "route info";
  size_t aad_size = strlen(aad);
  const char* message = "Hello world";
  size_t message_size = strlen(message);

  uint32_t session_id, frame_iv;
  uint8_t ciphertext[64];
  uint8_t auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  char plaintext[64];

  assert_ok(cubicrypt_out_encode_copy(sender, &session_id, &frame_iv, true, aad,
                                      aad_size, message, message_size, auth_tag,
                                      ciphertext));

  cubicrypt_err result = cubicrypt_in_decode_copy(
      receiver, session_id, frame_iv, true, aad, aad_size, ciphertext,
      message_size, auth_tag, plaintext);

  if (result == CUBICRYPT_ERR_OK) {
    assert(memcmp(message, plaintext, message_size) == 0);
  }

  return result;
}

CUBICRYPT_TEST_MAIN(receiver_crash) {
  cubicrypt_out_ctx sender;
  cubicrypt_session_state sender_persistent_state =
      cubicrypt_initial_persistent_state();
  assert_ok(cubicrypt_out_init(&sender, test_primary_key, &default_params,
                               load_session_state, save_session_state,
                               &sender_persistent_state));

  cubicrypt_in_ctx receiver;
  cubicrypt_session_state receiver_persistent_state =
      cubicrypt_initial_persistent_state();
  assert_ok(cubicrypt_in_init(&receiver, test_primary_key, &default_params,
                              load_session_state, save_session_state,
                              &receiver_persistent_state));

  uint32_t first_session_id = 0xf1abcdef;
  assert_ok(cubicrypt_out_new_session(&sender, first_session_id));

  // Transmit a few frames so the receiver knows about the session ID.
  for (uint32_t i = 0; i < 5; i++) {
    assert_ok(send_and_receive(&sender, &receiver));
  }

  // Now simulate five crashes.
  for (uint32_t i = 0; i < 5; i++) {
    memset(&receiver, 0, sizeof(receiver));
    assert_ok(cubicrypt_in_init(&receiver, test_primary_key, &default_params,
                                load_session_state, save_session_state,
                                &receiver_persistent_state));
  }

  // Because the receiver "crashed" five times, it wasted five session IDs.
  // Therefore, decoding should fail for the current and the next four sessions.
  for (uint32_t i = 0; i < 5; i++) {
    // Decoding should fail because the session ID is not safe.
    assert_eq(CUBICRYPT_ERR_AUTH, send_and_receive(&sender, &receiver));

    // We cannot create a new session with the same ID.
    assert_eq(CUBICRYPT_ERR_PARAMS,
              cubicrypt_out_new_session(&sender, first_session_id + i));

    // Create a new session with the next possible ID.
    assert_ok(cubicrypt_out_new_session(&sender, first_session_id + i + 1));
  }

  // The sixth session ID should be valid.
  assert_ok(send_and_receive(&sender, &receiver));
}
