#include "common.h"

static const char aad[] = "some route";
static const size_t aad_size = sizeof(aad) - 1;
static const char message[] = "Hello world";
static const size_t message_size = sizeof(message) - 1;

#ifndef CUBICRYPT_NO_OUT_OF_ORDER
static void test_internals(void) {
  // Initialize sender and receiver to some valid state and exchange one frame.
  uint32_t session_id = 12345, frame_iv = 67890;

  cubicrypt_out_ctx sender;
  cubicrypt_session_state sender_persistent_state = { session_id, frame_iv };
  assert_ok(cubicrypt_out_init(&sender, test_primary_key, &default_params,
                               load_session_state, save_session_state,
                               &sender_persistent_state));

  cubicrypt_in_ctx receiver;
  cubicrypt_session_state receiver_persistent_state = { session_id, frame_iv };
  assert_ok(cubicrypt_in_init(&receiver, test_primary_key, &default_params,
                              load_session_state, save_session_state,
                              &receiver_persistent_state));
  assert_eq(receiver.smallest_valid_session_state.id, session_id);
  assert_eq(receiver.smallest_valid_session_state.iv, frame_iv);
  assert_eq(receiver.ooo_window, 0);

  uint8_t auth[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  assert_ok(cubicrypt_out_auth_only(&sender, &session_id, &frame_iv, aad,
                                    aad_size, message, message_size, auth));
  assert_eq(session_id, 12345);
  assert_eq(frame_iv, 67890);

  assert_ok(cubicrypt_in_verify_only(&receiver, session_id, frame_iv, aad,
                                     aad_size, message, message_size, auth));
  assert_eq(receiver.smallest_valid_session_state.id, session_id);
  assert_eq(receiver.smallest_valid_session_state.iv, frame_iv + 1);
  assert_eq(receiver.ooo_window, 0);

  // Attempting to decode the same frame more than once should fail.
  assert_eq(CUBICRYPT_ERR_AUTH,
            cubicrypt_in_verify_only(&receiver, session_id, frame_iv, aad,
                                     aad_size, message, message_size, auth));
  assert_eq(receiver.smallest_valid_session_state.id, session_id);
  assert_eq(receiver.smallest_valid_session_state.iv, frame_iv + 1);
  assert_eq(receiver.ooo_window, 0);

  // Authenticate two frames and receive them out of order.
  uint8_t skipped_auth[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  uint32_t skipped_frame_iv;
  assert_ok(cubicrypt_out_auth_only(&sender, &session_id, &skipped_frame_iv,
                                    aad, aad_size, message, message_size,
                                    skipped_auth));
  assert_eq(session_id, 12345);
  assert_eq(skipped_frame_iv, frame_iv + 1);
  assert_ok(cubicrypt_out_auth_only(&sender, &session_id, &frame_iv, aad,
                                    aad_size, message, message_size, auth));
  assert_eq(session_id, 12345);
  assert_eq(frame_iv, skipped_frame_iv + 1);

  assert_ok(cubicrypt_in_verify_only(&receiver, session_id, frame_iv, aad,
                                     aad_size, message, message_size, auth));
  assert_eq(receiver.smallest_valid_session_state.id, session_id);
  assert_eq(receiver.smallest_valid_session_state.iv, frame_iv + 1);
  assert_eq(receiver.ooo_window, 1);

  assert_ok(cubicrypt_in_verify_only(&receiver, session_id, skipped_frame_iv,
                                     aad, aad_size, message, message_size,
                                     skipped_auth));
  assert_eq(receiver.smallest_valid_session_state.id, session_id);
  assert_eq(receiver.smallest_valid_session_state.iv, frame_iv + 1);
  assert_eq(receiver.ooo_window, 0);

  // Authenticate another frame but receive CUBICRYPT_OUT_OF_ORDER_WINDOW_BITS
  // subsequent frames first.
  assert_ok(cubicrypt_out_auth_only(&sender, &session_id, &skipped_frame_iv,
                                    aad, aad_size, message, message_size,
                                    skipped_auth));
  assert_eq(session_id, 12345);
  assert_eq(skipped_frame_iv, frame_iv + 1);

  for (uint32_t i = 0; i < CUBICRYPT_OUT_OF_ORDER_WINDOW_BITS; i++) {
    assert_ok(cubicrypt_out_auth_only(&sender, &session_id, &frame_iv, aad,
                                      aad_size, message, message_size, auth));
    assert_eq(session_id, 12345);
    assert_eq(frame_iv, skipped_frame_iv + 1 + i);

    assert_ok(cubicrypt_in_verify_only(&receiver, session_id, frame_iv, aad,
                                       aad_size, message, message_size, auth));
    assert_eq(receiver.smallest_valid_session_state.id, session_id);
    assert_eq(receiver.smallest_valid_session_state.iv, frame_iv + 1);
    assert_eq(receiver.ooo_window, (cubicrypt_ooo_window) 1u << i);
  }

  // We should still be able to verify the authenticity of the previously
  // authenticated frame after having seen CUBICRYPT_OUT_OF_ORDER_WINDOW_BITS
  // subsequent frames.
  assert_ok(cubicrypt_in_verify_only(&receiver, session_id, skipped_frame_iv,
                                     aad, aad_size, message, message_size,
                                     skipped_auth));
  assert_eq(receiver.smallest_valid_session_state.id, session_id);
  assert_eq(receiver.smallest_valid_session_state.iv, frame_iv + 1);
  assert_eq(receiver.ooo_window, 0);

  // Fill the out-of-order window with some bit pattern.
  cubicrypt_ooo_window past = 0;
  for (uint32_t i = 0; i < 5 * CUBICRYPT_OUT_OF_ORDER_WINDOW_BITS; i++) {
    assert_ok(cubicrypt_out_auth_only(&sender, &session_id, &frame_iv, aad,
                                      aad_size, message, message_size, auth));
    assert_eq(session_id, 12345);

    bool skip = i % 2 != (i + 1) % 3;
    if (!skip) {
      assert_ok(cubicrypt_in_verify_only(&receiver, session_id, frame_iv, aad,
                                         aad_size, message, message_size,
                                         auth));
      assert_eq(receiver.smallest_valid_session_state.id, session_id);
      assert_eq(receiver.smallest_valid_session_state.iv, frame_iv + 1);
      assert_eq(receiver.ooo_window, past);
    }
    past = (past << 1u) | (cubicrypt_ooo_window) skip;
  }

  // Starting a new session should erase the window.
  assert_ok(cubicrypt_out_new_session(&sender, session_id + 1));
  assert_ok(cubicrypt_out_auth_only(&sender, &session_id, &frame_iv, aad,
                                    aad_size, message, message_size, auth));
  assert_eq(session_id, 12346);
  assert_eq(frame_iv, 0);

  assert_ok(cubicrypt_in_verify_only(&receiver, session_id, frame_iv, aad,
                                     aad_size, message, message_size, auth));
  assert_eq(receiver.smallest_valid_session_state.id, session_id);
  assert_eq(receiver.smallest_valid_session_state.iv, frame_iv + 1);
  assert_eq(receiver.ooo_window, 0);
}
#endif

static inline void generate_auth_tag(
    uint32_t session_id, uint32_t frame_iv,
    uint8_t auth[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES]) {
  cubicrypt_out_ctx sender;
  cubicrypt_session_state sender_persistent_state = { session_id, frame_iv };
  assert_ok(cubicrypt_out_init(&sender, test_primary_key, &default_params,
                               load_session_state, save_session_state,
                               &sender_persistent_state));

  uint32_t actual_session_id, actual_frame_iv;
  assert_ok(cubicrypt_out_auth_only(&sender, &actual_session_id,
                                    &actual_frame_iv, aad, aad_size, message,
                                    message_size, auth));
  assert_eq(actual_session_id, session_id);
  assert_eq(actual_frame_iv, frame_iv);
}

/** Deterministically shuffles an array using Donald Knuth' MMIX LCG. */
static inline void shuffle(uint32_t* array, size_t n) {
  uint64_t mmix = n;
  for (size_t i = 1; i < n; i++) {
    mmix = mmix * UINT64_C(0x5851f42d4c957f2d) + UINT64_C(0x14057b7ef767814f);
    size_t j = (size_t) (mmix % i);
    uint32_t tmp = array[i];
    array[i] = array[j];
    array[j] = tmp;
  }
}

static void test_black_box(void) {
  uint32_t session_id = 1234;
  cubicrypt_in_ctx receiver;
  cubicrypt_session_state receiver_persistent_state = { session_id, 0 };
  assert_ok(cubicrypt_in_init(&receiver, test_primary_key, &default_params,
                              load_session_state, save_session_state,
                              &receiver_persistent_state));

  // Create a pseudo-random permutation of the the first
  // 5 * CUBICRYPT_OUT_OF_ORDER_WINDOW_BITS frame sequence numbers.
#ifndef CUBICRYPT_NO_OUT_OF_ORDER
  uint32_t frame_ivs[5 * CUBICRYPT_OUT_OF_ORDER_WINDOW_BITS];
#else
  uint32_t frame_ivs[40];
#endif
  const size_t n_frame_ivs = sizeof(frame_ivs) / sizeof(*frame_ivs);
  for (size_t i = 0; i < n_frame_ivs; i++) {
    frame_ivs[i] = i;
  }
  shuffle(frame_ivs, n_frame_ivs);

  // Try to decode the frames in the order of the permutation. Whether or not
  // the decoding of any particular frame succeeds depends on the order of the
  // frames, but in any case, we expect to see either case many times.
  uint32_t max_frame_iv_plus_one = 0;
  for (size_t i = 0; i < n_frame_ivs; i++) {
    uint8_t auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
    generate_auth_tag(session_id, frame_ivs[i], auth_tag);

#ifndef CUBICRYPT_NO_OUT_OF_ORDER
    bool should_be_ok = (frame_ivs[i] >= max_frame_iv_plus_one) ||
                        (max_frame_iv_plus_one - frame_ivs[i] <=
                         CUBICRYPT_OUT_OF_ORDER_WINDOW_BITS + 1);
#else
    bool should_be_ok = (frame_ivs[i] >= max_frame_iv_plus_one);
#endif
    int err =
        cubicrypt_in_verify_only(&receiver, session_id, frame_ivs[i], aad,
                                 aad_size, message, message_size, auth_tag);
    if (should_be_ok) {
      assert_ok(err);
      if (max_frame_iv_plus_one <= frame_ivs[i]) {
        max_frame_iv_plus_one = frame_ivs[i] + 1;
      }
    } else {
      assert_eq(err, CUBICRYPT_ERR_AUTH);
    }
  }
}

CUBICRYPT_TEST_MAIN(out_of_order) {
#ifndef CUBICRYPT_NO_OUT_OF_ORDER
  test_internals();
#endif
  test_black_box();
}
