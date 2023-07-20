#ifndef __TEST__COMMON_H__
#define __TEST__COMMON_H__

#include "../include/cubicrypt.h"

#undef NDEBUG
#include <assert.h>

#define assert_eq(a, b) assert((a) == (b))
#define assert_ok(x) assert_eq(CUBICRYPT_ERR_OK, (x))

#ifndef CUBICRYPT_EMBEDDABLE_TEST
#  define CUBICRYPT_TEST_MAIN(name)                                            \
    void cubicrypt_test_##name(void);                                          \
    int main(void) {                                                           \
      cubicrypt_test_##name();                                                 \
      return 0;                                                                \
    }                                                                          \
    void cubicrypt_test_##name(void)
#else
#  define CUBICRYPT_TEST_MAIN(name) void cubicrypt_test_##name(void)
#endif

#ifndef _MSC_VER
#  define MAYBE_UNUSED __attribute__((unused))
#else
#  define MAYBE_UNUSED
#endif

static const uint8_t test_primary_key[CUBICRYPT_PRIMARY_KEY_BYTES] = {
  0xc8, 0xbb, 0xa8, 0xc0, 0x06, 0xef, 0x1b, 0x7c, 0x71, 0x11, 0xfd,
  0xf3, 0xe8, 0x92, 0x7a, 0xe9, 0x32, 0x71, 0xb1, 0x8b, 0x01, 0x4f,
  0x0a, 0x21, 0x0a, 0x05, 0x7a, 0x59, 0x1a, 0x37, 0x41, 0x07
};

static const cubicrypt_params default_params = {
  .context_id = { 'g', 'n', 'd', '-', '>', 's', 'a', 't' },
  .epoch = 0,
  .session_id_bits = CUBICRYPT_MAX_SESSION_ID_BITS,
  .frame_iv_bits = CUBICRYPT_MAX_FRAME_IV_BITS
};

MAYBE_UNUSED static bool save_session_state(cubicrypt_session_state state,
                                            void* user_data) {
  cubicrypt_session_state* p = user_data;
  p->id = state.id;
  p->iv = state.iv;
  return true;
}

MAYBE_UNUSED static bool load_session_state(cubicrypt_session_state* state,
                                            void* user_data) {
  cubicrypt_session_state* p = user_data;
  state->id = p->id;
  state->iv = p->iv;
  return true;
}

#endif  // __TEST__COMMON_H__
