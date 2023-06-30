#include "common.h"

#include <string.h>

typedef struct {
  cubicrypt_session_state state;
  bool next_read_ok;
  bool next_write_ok;
} storage_data;

bool load_session_state_or_fail(cubicrypt_session_state* state,
                                void* user_data) {
  storage_data* data = user_data;

  if (!data->next_read_ok) {
    return false;
  }

  data->next_read_ok = false;

  return load_session_state(state, &data->state);
}

// TODO: It's probably better not to pass the state by value.
bool save_session_state_or_fail(cubicrypt_session_state state,
                                void* user_data) {
  storage_data* data = user_data;

  if (!data->next_write_ok) {
    return false;
  }

  data->next_write_ok = false;

  return save_session_state(state, &data->state);
}

CUBICRYPT_TEST_MAIN(storage_failure) {
  cubicrypt_out_ctx sender;
  storage_data sender_storage;
  cubicrypt_in_ctx receiver;
  storage_data receiver_storage;

  memset(&sender_storage, 0, sizeof(sender_storage));
  sender_storage.state = cubicrypt_initial_persistent_state();
  memset(&receiver_storage, 0, sizeof(receiver_storage));
  receiver_storage.state = cubicrypt_initial_persistent_state();

  // Initializing should fail until a read followed by a write succeeds.
  assert_eq(cubicrypt_out_init(&sender, test_primary_key, &default_params,
                               load_session_state_or_fail,
                               save_session_state_or_fail, &sender_storage),
            CUBICRYPT_ERR_STORAGE);
  sender_storage.next_read_ok = true;
  assert_eq(cubicrypt_out_init(&sender, test_primary_key, &default_params,
                               load_session_state_or_fail,
                               save_session_state_or_fail, &sender_storage),
            CUBICRYPT_ERR_STORAGE);
  sender_storage.next_write_ok = true;
  assert_eq(cubicrypt_out_init(&sender, test_primary_key, &default_params,
                               load_session_state_or_fail,
                               save_session_state_or_fail, &sender_storage),
            CUBICRYPT_ERR_STORAGE);
  sender_storage.next_read_ok = true;
  sender_storage.next_write_ok = true;
  assert_ok(cubicrypt_out_init(&sender, test_primary_key, &default_params,
                               load_session_state_or_fail,
                               save_session_state_or_fail, &sender_storage));

  // Initializing should fail until a read followed by a write succeeds.
  assert_eq(cubicrypt_in_init(&receiver, test_primary_key, &default_params,
                              load_session_state_or_fail,
                              save_session_state_or_fail, &receiver_storage),
            CUBICRYPT_ERR_STORAGE);
  receiver_storage.next_read_ok = true;
  assert_eq(cubicrypt_in_init(&receiver, test_primary_key, &default_params,
                              load_session_state_or_fail,
                              save_session_state_or_fail, &receiver_storage),
            CUBICRYPT_ERR_STORAGE);
  receiver_storage.next_write_ok = true;
  assert_eq(cubicrypt_in_init(&receiver, test_primary_key, &default_params,
                              load_session_state_or_fail,
                              save_session_state_or_fail, &receiver_storage),
            CUBICRYPT_ERR_STORAGE);
  receiver_storage.next_read_ok = true;
  receiver_storage.next_write_ok = true;
  assert_ok(cubicrypt_in_init(&receiver, test_primary_key, &default_params,
                              load_session_state_or_fail,
                              save_session_state_or_fail, &receiver_storage));

  // Run the actual test multiple times with different session IDs.
  for (unsigned int i = 2; i <= 1000; i++) {
    // As long as writing to the storage fails, it should not be possible to
    // start new sessions, and the internal state should remain unchanged.
    for (unsigned int j = 1; j <= 10; j++) {
      assert_eq(cubicrypt_out_new_session(&sender, i), CUBICRYPT_ERR_STORAGE);
    }

    // The previous, unsuccessful writes should not affect our ability to start
    // a new session (with the same identifier) as soon as writing succeeds.
    sender_storage.next_write_ok = true;
    assert_ok(cubicrypt_out_new_session(&sender, i));

    char body[] = "Hello world";
    char auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
    char ciphertext[sizeof(body)];
    char decrypted[sizeof(body)];
    uint32_t session_id, frame_iv;

    assert_ok(cubicrypt_out_encode_copy(&sender, &session_id, &frame_iv, true,
                                        NULL, 0, body, sizeof(body), auth_tag,
                                        ciphertext));

    // Similarly, the receiver cannot successfully receive frames belonging to a
    // new session until its own storage succeeds.
    for (unsigned int j = 1; j <= 10; j++) {
      assert_eq(cubicrypt_in_decode_copy(&receiver, session_id, frame_iv, true,
                                         NULL, 0, ciphertext, sizeof(body),
                                         auth_tag, decrypted),
                CUBICRYPT_ERR_STORAGE);
    }

    // The unsuccessfull attempts to decode this frame should not affect our
    // ability to decode it now that writing succeeds.
    receiver_storage.next_write_ok = true;
    assert_ok(cubicrypt_in_decode_copy(&receiver, session_id, frame_iv, true,
                                       NULL, 0, ciphertext, sizeof(body),
                                       auth_tag, decrypted));

    // Attempting to decrypt it yet again should fail now.
    assert_eq(
        cubicrypt_in_decode_copy(&receiver, session_id, frame_iv, true, NULL, 0,
                                 ciphertext, sizeof(body), auth_tag, decrypted),
        CUBICRYPT_ERR_AUTH);
  }

  assert_eq(cubicrypt_out_deinit(&sender), CUBICRYPT_ERR_STORAGE);
  sender_storage.next_write_ok = true;
  assert_ok(cubicrypt_out_deinit(&sender));

  assert_eq(cubicrypt_in_deinit(&receiver), CUBICRYPT_ERR_STORAGE);
  receiver_storage.next_write_ok = true;
  assert_ok(cubicrypt_in_deinit(&receiver));
}
