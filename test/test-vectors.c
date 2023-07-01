#include "test-vectors.h"

#include "common.h"

#include <string.h>

static void setup_params(cubicrypt_params* params,
                         const struct test_vector* t) {
  memcpy(params->context_id, t->context_id, CUBICRYPT_CONTEXT_ID_BYTES);
  params->epoch = t->epoch;
  params->session_id_bits = CUBICRYPT_MAX_SESSION_ID_BITS;
  params->frame_iv_bits = CUBICRYPT_MAX_FRAME_IV_BITS;
}

static void test_receive_inner(const struct test_vector* t,
                               void (*test_fn)(cubicrypt_in_ctx* receiver,
                                               const struct test_vector* t)) {
  cubicrypt_params params;
  setup_params(&params, t);

  cubicrypt_in_ctx receiver;
  cubicrypt_session_state receiver_persistent_state =
      cubicrypt_initial_persistent_state();
  assert_ok(cubicrypt_in_init(&receiver, t->primary_key, &params,
                              load_session_state, save_session_state,
                              &receiver_persistent_state));
  test_fn(&receiver, t);
  assert_ok(cubicrypt_in_deinit(&receiver));
}

static void test_receive_verify_decrypt(cubicrypt_in_ctx* receiver,
                                        const struct test_vector* t) {
  char plaintext[TEST_VECTOR_MAX_MESSAGE_SIZE];
  assert_ok(cubicrypt_in_verify_decrypt(receiver, t->session_id, t->frame_iv,
                                        t->aad, t->aad_size, t->e_ciphertext,
                                        t->message_size, t->e_tag, plaintext));
  assert_eq(0, memcmp(plaintext, t->message, t->message_size));
}

static void test_receive_verify_only(cubicrypt_in_ctx* receiver,
                                     const struct test_vector* t) {
  assert_ok(cubicrypt_in_verify_only(receiver, t->session_id, t->frame_iv,
                                     t->aad, t->aad_size, t->message,
                                     t->message_size, t->a_tag));
}

static void test_receive(const struct test_vector* t) {
  test_receive_inner(t, test_receive_verify_decrypt);
  test_receive_inner(t, test_receive_verify_only);
}

static void test_send_inner(const struct test_vector* t,
                            void (*test_fn)(cubicrypt_out_ctx* sender,
                                            const struct test_vector* t)) {
  cubicrypt_params params;
  setup_params(&params, t);

  cubicrypt_out_ctx sender;
  cubicrypt_session_state sender_persistent_state = { t->session_id,
                                                      t->frame_iv };
  assert_ok(cubicrypt_out_init(&sender, t->primary_key, &params,
                               load_session_state, save_session_state,
                               &sender_persistent_state));
  test_fn(&sender, t);
  assert_ok(cubicrypt_out_deinit(&sender));
}

static void test_send_auth_encrypt(cubicrypt_out_ctx* sender,
                                   const struct test_vector* t) {
  uint32_t session_id, frame_iv;
  uint8_t ciphertext[TEST_VECTOR_MAX_MESSAGE_SIZE];
  uint8_t auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  assert_ok(cubicrypt_out_auth_encrypt(sender, &session_id, &frame_iv, t->aad,
                                       t->aad_size, t->message, t->message_size,
                                       auth_tag, ciphertext));
  assert_eq(session_id, t->session_id);
  assert_eq(frame_iv, t->frame_iv);
  assert_eq(0, memcmp(ciphertext, t->e_ciphertext, t->message_size));
  assert_eq(0, memcmp(auth_tag, t->e_tag, CUBICRYPT_AES_GCM_AUTH_TAG_BYTES));
}

static void test_send_auth_only(cubicrypt_out_ctx* sender,
                                const struct test_vector* t) {
  uint32_t session_id, frame_iv;
  uint8_t auth_tag[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  assert_ok(cubicrypt_out_auth_only(sender, &session_id, &frame_iv, t->aad,
                                    t->aad_size, t->message, t->message_size,
                                    auth_tag));
  assert_eq(session_id, t->session_id);
  assert_eq(frame_iv, t->frame_iv);
  assert_eq(0, memcmp(auth_tag, t->a_tag, CUBICRYPT_AES_GCM_AUTH_TAG_BYTES));
}

static void test_send(const struct test_vector* t) {
  test_send_inner(t, test_send_auth_encrypt);
  test_send_inner(t, test_send_auth_only);
}

CUBICRYPT_TEST_MAIN(vectors) {
  size_t n_vectors = sizeof(test_vectors) / sizeof(struct test_vector);
  assert_eq(n_vectors, N_TEST_VECTORS);

  for (size_t i = 0; i < n_vectors; i++) {
    test_receive(&test_vectors[i]);
    test_send(&test_vectors[i]);
  }
}
