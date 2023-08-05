OBJECTS = common/cpu_endian.o common/os_port_posix.o cyclone_crypto/aead/gcm.o \
          cyclone_crypto/cipher/aes.o cyclone_crypto/ecc/curve25519.o \
          cyclone_crypto/ecc/x25519.o cyclone_crypto/hash/sha256.o \
          cyclone_crypto/mac/gmac.o

CFLAGS = -Wall -Wextra -pedantic -Wno-error -Iconfig -Icommon -Icyclone_crypto

libcyclonecrypto.a: libcyclonecrypto-cubicrypt-ci-only.a
	ln -sf $< $@

libcyclonecrypto-cubicrypt-ci-only.a: $(OBJECTS)
	$(AR) rcs $@ $^

.PHONY: clean
clean:
	rm -f $(OBJECTS) libcyclonecrypto.a libcyclonecrypto-cubicrypt-ci-only.a
