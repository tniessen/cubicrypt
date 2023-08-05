#include "common.h"

#include <string.h>

CUBICRYPT_TEST_MAIN(basics) {
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

  uint32_t session_id;
  uint32_t session_iv;
  uint8_t auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  uint8_t ciphertext[128];
  uint8_t plaintext[128];

  {
    const char* aad = "some route";
    size_t aad_size = strlen(aad);
    const char* message = "Hello world";
    size_t message_size = strlen("Hello world");
    assert_ok(cubicrypt_out_encode_copy(&sender, &session_id, &session_iv, true,
                                        aad, aad_size, message, message_size,
                                        auth_tag, ciphertext));

    assert_ok(cubicrypt_in_decode_copy(&receiver, session_id, session_iv, true,
                                       aad, aad_size, ciphertext, message_size,
                                       auth_tag, plaintext));
    assert(memcmp(plaintext, message, message_size) == 0);

    assert_eq(CUBICRYPT_ERR_AUTH,
              cubicrypt_in_decode_copy(&receiver, session_id, session_iv, true,
                                       aad, aad_size, ciphertext, message_size,
                                       auth_tag, plaintext));

    assert_ok(cubicrypt_out_encode_copy(&sender, &session_id, &session_iv, true,
                                        aad, aad_size, message, message_size,
                                        auth_tag, ciphertext));
    assert_ok(cubicrypt_in_decode_copy(&receiver, session_id, session_iv, true,
                                       aad, aad_size, ciphertext, message_size,
                                       auth_tag, plaintext));
    assert(memcmp(plaintext, message, message_size) == 0);

    assert_ok(cubicrypt_out_encode_copy(&sender, &session_id, &session_iv,
                                        false, NULL, 0, message, message_size,
                                        auth_tag, ciphertext));
    assert_ok(cubicrypt_in_decode_copy(&receiver, session_id, session_iv, false,
                                       NULL, 0, ciphertext, message_size,
                                       auth_tag, plaintext));
    assert(memcmp(plaintext, message, message_size) == 0);
    // TODO: assert that the auth_tag is correct
  }

  // Test AAD padding.
  for (size_t aad_size = 0; aad_size <= 32; aad_size++) {
    for (size_t message_size = 0; message_size <= 32; message_size++) {
      uint8_t aad[32];
      memset(aad, 0xab ^ (int) aad_size, aad_size);
      uint8_t message[32];
      memset(message, 0xcd ^ (int) message_size, message_size);
      assert_ok(cubicrypt_out_auth_only(&sender, &session_id, &session_iv, aad,
                                        aad_size, message, message_size,
                                        auth_tag));
      assert_ok(cubicrypt_in_verify_only(&receiver, session_id, session_iv, aad,
                                         aad_size, message, message_size,
                                         auth_tag));
    }
  }

  assert_ok(cubicrypt_out_deinit(&sender));
  assert_eq(CUBICRYPT_ERR_PARAMS, cubicrypt_out_deinit(&sender));

  assert_ok(cubicrypt_in_deinit(&receiver));
  assert_eq(CUBICRYPT_ERR_PARAMS, cubicrypt_in_deinit(&receiver));
}
