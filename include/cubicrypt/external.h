#ifndef __CUBICRYPT_EXTERNAL_H__
#define __CUBICRYPT_EXTERNAL_H__

#include <cubicrypt/config.h>

#ifndef CUBICRYPT_EXTERN
// Applications that consume this header file likely do not want to mark the
// functions as extern. This macro is defined in src/crypto/{cmox,mbedtls}.c.
#  define CUBICRYPT_EXTERN
#endif

#ifndef CUBICRYPT_NO_KEY_EXCHANGE
#  if defined(CUBICRYPT_CRYPTO_BACKEND_IS_CMOX)

#    include <stddef.h>
#    include <stdint.h>

/**
 * Gathers entropy from an application-specific entropy source.
 *
 * This function may, but does not need to, overwrite the entire buffer with
 * random data. It is important that the function returns an estimate of the
 * amount of entropy that was gathered, regardless of how much of the given
 * buffer has been overwritten. For example, for a perfect entropy source, the
 * function should always return the size of the buffer in bits (8 * size). In
 * reality, however, the entropy source will not be perfect, and might be far
 * from it especially on embedded devices. In this case, the application should
 * error on the low side.
 *
 * The function must return at least 1 bit of entropy and at most 8 * size. A
 * return value of 0 is considered an error, and a return value exceeding
 * 8 * size indicates a bug in the implementation.
 *
 * @param[out] buf The buffer to fill with entropy.
 * @param[in] size The size of the buffer in bytes.
 * @return The estimated amount of entropy that was gathered, in bits.
 */
CUBICRYPT_EXTERN uint32_t __cubicrypt_secure_entropy(void* buf, size_t size);

#  elif defined(CUBICRYPT_CRYPTO_BACKEND_IS_MBEDTLS)

#    include <mbedtls/mbedtls_config.h>

#    include <stdbool.h>
#    include <stddef.h>

/**
 * An Mbed-TLS compatible entropy function.
 *
 * @param[in] ctx A user-defined context pointer.
 * @param[out] buf The buffer to fill with entropy.
 * @param[in] size The size of the buffer in bytes.
 * @return 0 on success, or an Mbed-TLS error code.
 */
typedef int (*cubicrypt_mbedtls_entropy_func)(void* ctx, unsigned char* buf,
                                              size_t size);

#    if defined(MBEDTLS_NO_PLATFORM_ENTROPY)

/**
 * Provides an entropy function and context for Mbed-TLS to Cubicrypt.
 *
 * This function must be implemented by the application when the Mbed-TLS
 * platform entropy source is unavailable. Typically, an application will want
 * to initialize its own mbedtls_entropy_context and add an application-specific
 * entropy source to it using mbedtls_entropy_add_source(). However, any
 * Mbed-TLS compatible entropy function may be provided.
 *
 * @param[out] func A pointer to the entropy function.
 * @param[out] ctx A pointer to the entropy context (first argument of func).
 * @return true if the function was successful, false otherwise.
 */
CUBICRYPT_EXTERN bool __cubicrypt_get_mbedtls_entropy_func(
    cubicrypt_mbedtls_entropy_func* func, void** ctx);

#    endif

#  endif
#endif

#endif  // __CUBICRYPT_EXTERNAL_H__
