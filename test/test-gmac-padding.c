#include "common.h"

#include <string.h>

#define AES_GCM_BYTES_PER_BLOCK 16

void generate_auth_tag(const uint8_t* aad, size_t aad_size,
                       const uint8_t* message, size_t message_size,
                       uint8_t auth[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES]) {
  cubicrypt_out_ctx sender;
  cubicrypt_session_state sender_persistent_state = { 1234, 5678 };
  assert_ok(cubicrypt_out_init(&sender, test_primary_key, &default_params,
                               load_session_state, save_session_state,
                               &sender_persistent_state));

  uint32_t session_id, frame_iv;
  assert_ok(cubicrypt_out_auth_only(&sender, &session_id, &frame_iv, aad,
                                    aad_size, message, message_size, auth));
  assert_eq(session_id, 1234);
  assert_eq(frame_iv, 5678);
}

CUBICRYPT_TEST_MAIN(gmac_padding) {
  // This is a regression test for a design issue in the original prototype. In
  // auth-only mode, the original design used PKCS#7 padding for the AAD and
  // then appended the body: aad pad*pad body, where pad = 16 - aad_size % 16.
  // However, this is clearly not safe, as demonstrated by this test.
  // The updated design fixes this issue by choosing a different construction:
  // the first block encodes the length of the AAD, followed by the AAD itself
  // and padding such that the AAD ends at a block boundary, followed by the
  // body (without padding). This construction is similar to that used by
  // ChaCha20-Poly1305, but less efficient because AES-GCM itself will also pad
  // the input and encode its length after we have already done so.

  // The original design would generate a tag for (0*16) (16*16) (16*16).
  // The new design generates a tag for (0*15 16) (0*16) (16*16).
  uint8_t auth1[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  {
    uint8_t aad1[AES_GCM_BYTES_PER_BLOCK];
    memset(aad1, 0, AES_GCM_BYTES_PER_BLOCK);
    uint8_t message1[AES_GCM_BYTES_PER_BLOCK];
    memset(message1, AES_GCM_BYTES_PER_BLOCK, AES_GCM_BYTES_PER_BLOCK);
    generate_auth_tag(aad1, sizeof(aad1), message1, sizeof(message1), auth1);
  }

  // The original design would generate a tag for (0*16 16*16) (16*16) (*0).
  // The new design generates a tag for (0*15 32) (0*16 16*16).
  uint8_t auth2[CUBICRYPT_AES_GCM_AUTH_TAG_BYTES];
  {
    uint8_t aad2[2 * AES_GCM_BYTES_PER_BLOCK];
    memset(aad2, 0, AES_GCM_BYTES_PER_BLOCK);
    memset(aad2 + AES_GCM_BYTES_PER_BLOCK, AES_GCM_BYTES_PER_BLOCK,
           AES_GCM_BYTES_PER_BLOCK);
    generate_auth_tag(aad2, sizeof(aad2), NULL, 0, auth2);
  }

  // The original design would have produced the same authentication tag, which
  // is undesirable.
  assert(memcmp(auth1, auth2, CUBICRYPT_AES_GCM_AUTH_TAG_BYTES) != 0);
}
