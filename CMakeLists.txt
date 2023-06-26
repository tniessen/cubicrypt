cmake_minimum_required(VERSION 3.10)

project(cubicrypt)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

add_compile_options(-Wall -Wextra -pedantic -Werror)

# TODO: ubsan and KCC and clang-tidy

option(ENABLE_ASAN "Enable the AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable the Undefined Behavior Sanitizer" OFF)
option(ENABLE_VALGRIND "Run tests using valgrind" OFF)

if(ENABLE_ASAN AND ENABLE_VALGRIND)
  message(FATAL_ERROR "ENABLE_ASAN and ENABLE_VALGRIND are mutually exclusive")
endif()

if(ENABLE_ASAN)
  add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address)
endif()

if(ENABLE_UBSAN)
  add_compile_options(-fsanitize=undefined -fno-sanitize-recover=all)
  add_link_options(-fsanitize=undefined -fno-sanitize-recover=all)
endif()

add_library(cubicrypt "src/cubicrypt.c")

set(CRYPTO_BACKEND openssl CACHE STRING "Crypto library to link against")
set_property(CACHE CRYPTO_BACKEND PROPERTY STRINGS cmox
                                                   gcrypt
                                                   mbedtls
                                                   nettle
                                                   openssl)

if(CRYPTO_BACKEND STREQUAL "cmox")
  target_sources(cubicrypt PRIVATE "src/crypto/cmox.c")
  if(DEFINED CMOX_INCLUDE_DIR)
    target_include_directories(cubicrypt PRIVATE "${CMOX_INCLUDE_DIR}")
  endif()
elseif(CRYPTO_BACKEND STREQUAL "gcrypt")
  target_sources(cubicrypt PRIVATE "src/crypto/gcrypt.c")
  target_link_libraries(cubicrypt PRIVATE gcrypt)
elseif(CRYPTO_BACKEND STREQUAL "mbedtls")
  target_sources(cubicrypt PRIVATE "src/crypto/mbedtls.c")
  target_link_libraries(cubicrypt PRIVATE mbedcrypto)
elseif(CRYPTO_BACKEND STREQUAL "nettle")
  target_sources(cubicrypt PRIVATE "src/crypto/nettle.c")
  target_link_libraries(cubicrypt PRIVATE nettle)
elseif(CRYPTO_BACKEND STREQUAL "openssl")
  include(FindOpenSSL)
  target_link_libraries(cubicrypt PRIVATE OpenSSL::Crypto)
  target_sources(cubicrypt PRIVATE "src/crypto/openssl.c")
else()
  message(FATAL_ERROR "Invalid CRYPTO_BACKEND")
endif()

option(ENABLE_TESTING "Enable testing" ON)
if(ENABLE_TESTING)
  enable_testing()
  list(APPEND CMAKE_CTEST_ARGUMENTS "--output-on-failure")
  file(GLOB test_files "test/test-*.c")
  foreach(file ${test_files})
    get_filename_component(fname ${file} NAME_WE)
    add_executable(${fname} ${file})
    target_link_libraries(${fname} PRIVATE cubicrypt)
    add_test(NAME ${fname} COMMAND $<TARGET_FILE:${fname}>)
    set_tests_properties("${fname}" PROPERTIES TIMEOUT 60)

    if(ENABLE_VALGRIND)
      add_test(NAME "valgrind:${fname}" COMMAND valgrind $<TARGET_FILE:${fname}>)
      set_tests_properties("valgrind:${fname}" PROPERTIES TIMEOUT 180)
    endif()
  endforeach()
endif()

option(ENABLE_EMBEDDABLE_SELF_TEST "Build the embeddable self-test" OFF)
if(ENABLE_EMBEDDABLE_SELF_TEST)
  file(GLOB test_files "test/test-*.c")
  set(test_decls "")
  set(test_calls "")
  foreach(file ${test_files})
    get_filename_component(fname ${file} NAME_WE)
    string(REGEX REPLACE "^test-|\\.c$" "" fname ${fname})
    string(REPLACE "-" "_" fname ${fname})
    list(APPEND test_decls "extern void cubicrypt_test_${fname}(void)")
    list(APPEND test_calls "cubicrypt_test_${fname}()")
  endforeach()
  list(JOIN test_decls ";\n" test_decls)
  list(JOIN test_calls ";\n" test_calls)
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/cubicrypt-embeddable-test.c" "${test_decls};\nvoid cubicrypt_run_all_tests(void) {\n${test_calls};\n}\n")
  add_library(cubicrypt-embeddable-test ${test_files}
                                        "${CMAKE_CURRENT_BINARY_DIR}/cubicrypt-embeddable-test.c")
  target_compile_definitions(cubicrypt-embeddable-test PRIVATE CUBICRYPT_EMBEDDABLE_TEST)
endif()
