#include "common.h"

#include <string.h>

CUBICRYPT_TEST_MAIN(sender_crash) {
  cubicrypt_out_ctx sender;
  cubicrypt_session_state sender_persistent_state = { 5000, 123 };
  assert_ok(cubicrypt_out_init(&sender, test_primary_key, &default_params,
                               load_session_state, save_session_state,
                               &sender_persistent_state));

  assert(sender_persistent_state.id == 5001);
  assert(sender_persistent_state.iv == 0);

  // The sender should encode using the previous persistent state, not the
  // currently stored persistent state.
  const char* aad = "foo";
  size_t aad_size = strlen(aad);
  uint8_t message[7] = { 1, 2, 3, 4, 5, 6, 7 };
  size_t message_size = sizeof(message);
  uint8_t ciphertext[7];
  uint8_t auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  uint32_t session_id;
  uint32_t frame_iv;
  assert_ok(cubicrypt_out_encode_copy(&sender, &session_id, &frame_iv, true,
                                      aad, aad_size, message, message_size,
                                      auth_tag, ciphertext));
  assert(session_id == 5000);
  assert(frame_iv == 123);

  // Now simulate five crashes.
  for (unsigned int i = 1; i <= 5; i++) {
    memset(&sender, 0, sizeof(sender));
    assert_ok(cubicrypt_out_init(&sender, test_primary_key, &default_params,
                                 load_session_state, save_session_state,
                                 &sender_persistent_state));
    assert(sender_persistent_state.id == 5001 + i);
    assert(sender_persistent_state.iv == 0);
  }

  // On each "crash", the sender loses the current session.
  // Five crashes mean that the new session ID is five higher.
  assert_ok(cubicrypt_out_encode_copy(&sender, &session_id, &frame_iv, true,
                                      aad, aad_size, message, message_size,
                                      auth_tag, ciphertext));
  assert(session_id == 5005);
  assert(frame_iv == 0);

  // Starting a new session with an ID that's not higher than the current one
  // should fail. This is a potential issue for systems that crash more often
  // than once per second and that use a timestamp as the session ID.
  assert_eq(CUBICRYPT_ERR_PARAMS, cubicrypt_out_new_session(&sender, 5005));
  assert_eq(CUBICRYPT_ERR_PARAMS, cubicrypt_out_new_session(&sender, 5004));

  // Starting a new session with a higher ID should be possible.
  assert_ok(cubicrypt_out_new_session(&sender, 5006));
  assert(sender_persistent_state.id == 5007);
  assert(sender_persistent_state.iv == 0);
}
