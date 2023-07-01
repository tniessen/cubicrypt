#include "common.h"

static const char aad[] = "some route";
static const size_t aad_size = sizeof(aad) - 1;
static const char message[] = "Hello world";
static const size_t message_size = sizeof(message) - 1;

static inline void exhaust_single_session(cubicrypt_out_ctx* sender,
                                          cubicrypt_in_ctx* receiver,
                                          uint32_t expected_session_id) {
  assert_eq(sender->next_valid_session_state.iv, 0);

  // Use up all frames within the current session.
  for (uint32_t i = 0; i < (1u << CUBICRYPT_MIN_FRAME_IV_BITS); i++) {
    uint32_t session_id, frame_iv;
    uint8_t auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
    assert_ok(cubicrypt_out_auth_only(sender, &session_id, &frame_iv, aad,
                                      aad_size, message, message_size,
                                      auth_tag));
    assert_eq(session_id, expected_session_id);
    assert_eq(frame_iv, i);

    assert_ok(cubicrypt_in_verify_only(receiver, session_id, frame_iv, aad,
                                       aad_size, message, message_size,
                                       auth_tag));
    assert_eq(receiver->smallest_valid_session_state.id,
              sender->next_valid_session_state.id);
    assert_eq(receiver->smallest_valid_session_state.iv,
              sender->next_valid_session_state.iv);
  }

  assert_eq(sender->next_valid_session_state.iv, 0);
}

static inline void test_with_session_id_bits(uint8_t session_id_bits) {
  cubicrypt_params params = { .context_id = { 0 },
                              .epoch = 1234u,
                              .session_id_bits = session_id_bits,
                              .frame_iv_bits = CUBICRYPT_MIN_FRAME_IV_BITS };

  cubicrypt_out_ctx sender;
  cubicrypt_session_state sender_persistent_state =
      cubicrypt_initial_persistent_state();
  assert_ok(cubicrypt_out_init(&sender, test_primary_key, &params,
                               load_session_state, save_session_state,
                               &sender_persistent_state));

  cubicrypt_in_ctx receiver;
  cubicrypt_session_state receiver_persistent_state =
      cubicrypt_initial_persistent_state();
  assert_ok(cubicrypt_in_init(&receiver, test_primary_key, &params,
                              load_session_state, save_session_state,
                              &receiver_persistent_state));

  // Use up all session identifiers, skipping most of them.
  uint32_t max_session_id = UINT32_C(0xffffffff) >> (32u - session_id_bits);
  uint32_t n_steps = 4;
  uint32_t step_size = max_session_id / n_steps;
  for (uint32_t i = 0; i <= n_steps; i++) {
    uint32_t session_id = max_session_id - step_size * (n_steps - i);
    assert_ok(cubicrypt_out_new_session(&sender, session_id));
    exhaust_single_session(&sender, &receiver, session_id);
    if (i < n_steps) {
      assert_eq(sender.next_valid_session_state.id, session_id + 1);
      assert_eq(sender_persistent_state.id, session_id + 2);
      assert_eq(receiver.smallest_valid_session_state.id, session_id + 1);
      assert_eq(receiver_persistent_state.id, session_id + 2);

      struct {
        uint32_t id;
        uint32_t iv;
        uint32_t max_id;
        uint32_t max_iv;
      } out_status, in_status;

      assert_ok(cubicrypt_out_get_session_status(
          &sender, &out_status.id, &out_status.iv, &out_status.max_id,
          &out_status.max_iv));
      assert_eq(out_status.id, session_id + 1);
      assert_eq(out_status.iv, 0);
      assert_eq(out_status.max_id, max_session_id);
      assert_eq(out_status.max_iv, 0xffu);

      assert_ok(cubicrypt_in_get_session_status(
          &receiver, &in_status.id, &in_status.iv, &in_status.max_id,
          &in_status.max_iv));
      assert_eq(in_status.id, session_id + 1);
      assert_eq(in_status.iv, 0);
      assert_eq(in_status.max_id, max_session_id);
      assert_eq(in_status.max_iv, 0xffu);
    }
  }

  // Usually, the safe recovery state that is written to persistent storage
  // would be different from the next valid session state. However, since we
  // have exhausted all session identifiers, both should be set to {0, 0}.
  assert_eq(sender.next_valid_session_state.id, 0);
  assert_eq(sender.next_valid_session_state.iv, 0);
  assert_eq(sender_persistent_state.id, 0);
  assert_eq(sender_persistent_state.iv, 0);

  // No more frames can be emitted.
  for (unsigned int i = 0; i < 5; i++) {
    uint32_t session_id, frame_iv;
    uint8_t auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
    assert_eq(
        CUBICRYPT_ERR_SESSIONS_EXHAUSTED,
        cubicrypt_out_auth_only(&sender, &session_id, &frame_iv, aad, aad_size,
                                message, message_size, auth_tag));
    assert_eq(sender.next_valid_session_state.id, 0);
    assert_eq(sender.next_valid_session_state.iv, 0);
    assert_eq(sender_persistent_state.id, 0);
    assert_eq(sender_persistent_state.iv, 0);

    assert_eq(
        CUBICRYPT_ERR_SESSIONS_EXHAUSTED,
        cubicrypt_out_get_session_status(&sender, NULL, NULL, NULL, NULL));

    // We cannot test the receiver directly, but we can inspect its status.
    assert_eq(
        CUBICRYPT_ERR_SESSIONS_EXHAUSTED,
        cubicrypt_in_get_session_status(&receiver, NULL, NULL, NULL, NULL));
  }
}

CUBICRYPT_TEST_MAIN(session_exhaustion) {
  for (uint8_t session_id_bits = CUBICRYPT_MIN_SESSION_ID_BITS;
       session_id_bits <= CUBICRYPT_MAX_SESSION_ID_BITS; session_id_bits++) {
    test_with_session_id_bits(session_id_bits);
  }
}
