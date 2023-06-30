#include "common.h"

#include <string.h>

static void test_invalid_params(void);

static void test_params(const cubicrypt_params* params);

CUBICRYPT_TEST_MAIN(params) {
  test_invalid_params();

  cubicrypt_params params;
  for (params.session_id_bits = CUBICRYPT_MIN_SESSION_ID_BITS;
       params.session_id_bits <= CUBICRYPT_MAX_SESSION_ID_BITS;
       params.session_id_bits++) {
    for (params.frame_iv_bits = CUBICRYPT_MIN_FRAME_IV_BITS;
         params.frame_iv_bits <= CUBICRYPT_MAX_FRAME_IV_BITS;
         params.frame_iv_bits++) {
      test_params(&params);
    }
  }
}

void test_invalid_params_instance(cubicrypt_params* params) {
  cubicrypt_out_ctx sender;
  assert_eq(CUBICRYPT_ERR_PARAMS,
            cubicrypt_out_init(&sender, test_primary_key, params,
                               load_session_state, save_session_state, NULL));

  cubicrypt_in_ctx receiver;
  assert_eq(CUBICRYPT_ERR_PARAMS,
            cubicrypt_in_init(&receiver, test_primary_key, params,
                              load_session_state, save_session_state, NULL));
}

void test_invalid_params(void) {
  cubicrypt_params params;

  // Too few session identifier bits.
  params.session_id_bits = CUBICRYPT_MIN_SESSION_ID_BITS - 1;
  params.frame_iv_bits = CUBICRYPT_MIN_FRAME_IV_BITS;
  test_invalid_params_instance(&params);

  // Too many session identifier bits.
  params.session_id_bits = CUBICRYPT_MAX_SESSION_ID_BITS + 1;
  params.frame_iv_bits = CUBICRYPT_MAX_FRAME_IV_BITS;
  test_invalid_params_instance(&params);

  // Too few frame counter bits.
  params.session_id_bits = CUBICRYPT_MAX_SESSION_ID_BITS;
  params.frame_iv_bits = CUBICRYPT_MIN_FRAME_IV_BITS - 1;
  test_invalid_params_instance(&params);

  // Too many frame counter bits.
  params.session_id_bits = CUBICRYPT_MIN_SESSION_ID_BITS;
  params.frame_iv_bits = CUBICRYPT_MAX_FRAME_IV_BITS + 1;
  test_invalid_params_instance(&params);
}

static void test_params(const cubicrypt_params* params) {
  // Initialize both contexts.
  cubicrypt_out_ctx sender;
  cubicrypt_session_state sender_persistent_state =
      cubicrypt_initial_persistent_state();
  assert_ok(cubicrypt_out_init(&sender, test_primary_key, params,
                               load_session_state, save_session_state,
                               &sender_persistent_state));
  cubicrypt_in_ctx receiver;
  cubicrypt_session_state receiver_persistent_state =
      cubicrypt_initial_persistent_state();
  assert_ok(cubicrypt_in_init(&receiver, test_primary_key, params,
                              load_session_state, save_session_state,
                              &receiver_persistent_state));

  // Encrypt and decrypt a few (empty) frames.
  uint32_t session_id, frame_iv;
  uint8_t auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  uint32_t i;
  for (i = 0; i < 100; i++) {
    assert_ok(cubicrypt_out_encode_copy(&sender, &session_id, &frame_iv, true,
                                        NULL, 0, NULL, 0, auth_tag, NULL));
    assert_ok(cubicrypt_in_decode_copy(&receiver, session_id, frame_iv, true,
                                       NULL, 0, NULL, 0, auth_tag, NULL));
  }

  // No matter how small the frame counter is, we have not exhausted the first
  // session.
  assert_eq(session_id, 1);
  assert_eq(frame_iv, i - 1);
  assert_eq(sender_persistent_state.id, 2);
  assert_eq(sender_persistent_state.iv, 0);
  assert_eq(receiver_persistent_state.id, 2);
  assert_eq(receiver_persistent_state.iv, 0);

  // We cannot really force Cubicrypt to skip frame IVs. Therefore, we shut the
  // sender down, modify the persistent state, and start it up again.
  assert_ok(cubicrypt_out_deinit(&sender));
  assert_eq(sender_persistent_state.id, 1);
  assert_eq(sender_persistent_state.iv, i);
  const uint32_t max_frame_iv =
      (params->frame_iv_bits == 32)
          ? (uint32_t) -1
          : (1u << (uint32_t) params->frame_iv_bits) - 1;
  sender_persistent_state.iv = max_frame_iv;
  assert_ok(cubicrypt_out_init(&sender, test_primary_key, params,
                               load_session_state, save_session_state,
                               &sender_persistent_state));

  // The "safe recovery state" of the sender should now refer to the next
  // session id.
  assert_eq(sender_persistent_state.id, 2);
  assert_eq(sender_persistent_state.iv, 0);

  // This should use the frame counter that we injected.
  assert_ok(cubicrypt_out_encode_copy(&sender, &session_id, &frame_iv, true,
                                      NULL, 0, NULL, 0, auth_tag, NULL));
  assert_eq(session_id, 1);
  assert_eq(frame_iv, max_frame_iv);

  // The sender must switch to the next session id now. This means that it must
  // update its recovery state.
  assert_eq(sender_persistent_state.id, 3);
  assert_eq(sender_persistent_state.iv, 0);

  // The receiver should silently skip the missing frames.
  assert_ok(cubicrypt_in_decode_copy(&receiver, session_id, frame_iv, true,
                                     NULL, 0, NULL, 0, auth_tag, NULL));

  // This should NOT result in an authentication error because the receiver
  // should reject the input simply because the frame counter is too large.
  // (Unless the frame counter has 32 bits, in which case this wraps around.)
  frame_iv++;
  assert_eq(cubicrypt_in_decode_copy(&receiver, session_id, frame_iv, true,
                                     NULL, 0, NULL, 0, auth_tag, NULL),
            (params->frame_iv_bits == 32) ? CUBICRYPT_ERR_AUTH
                                          : CUBICRYPT_ERR_PARAMS);

  // This should use the first frame counter of the next session id.
  assert_ok(cubicrypt_out_encode_copy(&sender, &session_id, &frame_iv, true,
                                      NULL, 0, NULL, 0, auth_tag, NULL));
  assert_eq(session_id, 2);
  assert_eq(frame_iv, 0);

  // There is no gap this time, the receiver should still decode correctly.
  assert_ok(cubicrypt_in_decode_copy(&receiver, session_id, frame_iv, true,
                                     NULL, 0, NULL, 0, auth_tag, NULL));

  // If the number of bits is less than 32, this session id would require more
  // bits than are available. If the number of bits is 32, this is equivalent
  // to 0, which cannot be a valid session id here.
  const uint32_t max_session_id =
      (params->session_id_bits == 32)
          ? (uint32_t) -1
          : (1u << (uint32_t) params->session_id_bits) - 1;
  assert_eq(cubicrypt_out_new_session(&sender, max_session_id + 1),
            CUBICRYPT_ERR_PARAMS);

  // Skip ahead to the last valid session id.
  assert_ok(cubicrypt_out_new_session(&sender, max_session_id));

  // TODO

  // Deinitialize both contexts.
  assert_ok(cubicrypt_out_deinit(&sender));
  assert_ok(cubicrypt_in_deinit(&receiver));
}
