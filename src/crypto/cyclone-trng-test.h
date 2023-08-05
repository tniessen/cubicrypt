// This file attempts to determine if the Cyclone TRNG is supported. The user
// can define CUBICRYPT_HAVE_CYCLONE_TRNG or CUBICRYPT_NO_CYCLONE_TRNG to
// override the automatic detection. If neither is set, we check for
// CRYPTO_TRNG_SUPPORT followed by hardware-specific macros that have been
// extracted from version 2.3.0 of CycloneCRYPTO.
// The following directives assume that crypto_config.h has been included
// already, directly or inndirectly.

#ifdef CUBICRYPT_NO_CYCLONE_TRNG
#  undef CUBICRYPT_HAVE_CYCLONE_TRNG
#else
#  ifndef CUBICRYPT_HAVE_CYCLONE_TRNG
#    ifndef DISABLED
#      define DISABLED 0
#    endif
#    ifdef CRYPTO_TRNG_SUPPORT
#      if (CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef APM32F4XX_CRYPTO_TRNG_SUPPORT
#      if (APM32F4XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef EFM32GG11_CRYPTO_TRNG_SUPPORT
#      if (EFM32GG11_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef ESP32_C3_CRYPTO_TRNG_SUPPORT
#      if (ESP32_C3_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef ESP32_C6_CRYPTO_TRNG_SUPPORT
#      if (ESP32_C6_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef ESP32_CRYPTO_TRNG_SUPPORT
#      if (ESP32_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef ESP32_S2_CRYPTO_TRNG_SUPPORT
#      if (ESP32_S2_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef ESP32_S3_CRYPTO_TRNG_SUPPORT
#      if (ESP32_S3_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef GD32F2XX_CRYPTO_TRNG_SUPPORT
#      if (GD32F2XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef GD32F4XX_CRYPTO_TRNG_SUPPORT
#      if (GD32F4XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef GD32W5XX_CRYPTO_TRNG_SUPPORT
#      if (GD32W5XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef LPC54XXX_CRYPTO_TRNG_SUPPORT
#      if (LPC54XXX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef LPC55XX_CRYPTO_TRNG_SUPPORT
#      if (LPC55XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef MIMXRT1020_CRYPTO_TRNG_SUPPORT
#      if (MIMXRT1020_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef MIMXRT1040_CRYPTO_TRNG_SUPPORT
#      if (MIMXRT1040_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef MIMXRT1050_CRYPTO_TRNG_SUPPORT
#      if (MIMXRT1050_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef MIMXRT1060_CRYPTO_TRNG_SUPPORT
#      if (MIMXRT1060_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef MIMXRT1160_CRYPTO_TRNG_SUPPORT
#      if (MIMXRT1160_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef MIMXRT1170_CRYPTO_TRNG_SUPPORT
#      if (MIMXRT1170_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef MK6X_CRYPTO_TRNG_SUPPORT
#      if (MK6X_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef MKV5X_CRYPTO_TRNG_SUPPORT
#      if (MKV5X_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef PIC32CM_LS_CRYPTO_TRNG_SUPPORT
#      if (PIC32CM_LS_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef PIC32CX_BZ_CRYPTO_TRNG_SUPPORT
#      if (PIC32CX_BZ_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef PIC32CX_MT_CRYPTO_TRNG_SUPPORT
#      if (PIC32CX_MT_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef PIC32CX_SG_CRYPTO_TRNG_SUPPORT
#      if (PIC32CX_SG_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef PIC32CZ_CRYPTO_TRNG_SUPPORT
#      if (PIC32CZ_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef PIC32MZ_CRYPTO_TRNG_SUPPORT
#      if (PIC32MZ_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef RA2_CRYPTO_TRNG_SUPPORT
#      if (RA2_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef RA4_CRYPTO_TRNG_SUPPORT
#      if (RA4_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef RA6_CRYPTO_TRNG_SUPPORT
#      if (RA6_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef RX65N_CRYPTO_TRNG_SUPPORT
#      if (RX65N_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef S32K1_CRYPTO_TRNG_SUPPORT
#      if (S32K1_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef S5D9_CRYPTO_TRNG_SUPPORT
#      if (S5D9_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef S7G2_CRYPTO_TRNG_SUPPORT
#      if (S7G2_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef SAM4C_CRYPTO_TRNG_SUPPORT
#      if (SAM4C_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef SAM4L_CRYPTO_TRNG_SUPPORT
#      if (SAM4L_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef SAM9X60_CRYPTO_TRNG_SUPPORT
#      if (SAM9X60_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef SAMA5D2_CRYPTO_TRNG_SUPPORT
#      if (SAMA5D2_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef SAMA5D3_CRYPTO_TRNG_SUPPORT
#      if (SAMA5D3_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef SAMD51_CRYPTO_TRNG_SUPPORT
#      if (SAMD51_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef SAME51_CRYPTO_TRNG_SUPPORT
#      if (SAME51_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef SAME53_CRYPTO_TRNG_SUPPORT
#      if (SAME53_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef SAME54_CRYPTO_TRNG_SUPPORT
#      if (SAME54_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef SAME70_CRYPTO_TRNG_SUPPORT
#      if (SAME70_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef SAML11_CRYPTO_TRNG_SUPPORT
#      if (SAML11_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef SAMV71_CRYPTO_TRNG_SUPPORT
#      if (SAMV71_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32F2XX_CRYPTO_TRNG_SUPPORT
#      if (STM32F2XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32F4XX_CRYPTO_TRNG_SUPPORT
#      if (STM32F4XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32F7XX_CRYPTO_TRNG_SUPPORT
#      if (STM32F7XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32G0XX_CRYPTO_TRNG_SUPPORT
#      if (STM32G0XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32G4XX_CRYPTO_TRNG_SUPPORT
#      if (STM32G4XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32H5XX_CRYPTO_TRNG_SUPPORT
#      if (STM32H5XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32H7XX_CRYPTO_TRNG_SUPPORT
#      if (STM32H7XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32L0XX_CRYPTO_TRNG_SUPPORT
#      if (STM32L0XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32L4XX_CRYPTO_TRNG_SUPPORT
#      if (STM32L4XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32L5XX_CRYPTO_TRNG_SUPPORT
#      if (STM32L5XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32MP1XX_CRYPTO_TRNG_SUPPORT
#      if (STM32MP1XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32U5XX_CRYPTO_TRNG_SUPPORT
#      if (STM32U5XX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32WBAXX_CRYPTO_TRNG_SUPPORT
#      if (STM32WBAXX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32WBXX_CRYPTO_TRNG_SUPPORT
#      if (STM32WBXX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#    ifdef STM32WLXX_CRYPTO_TRNG_SUPPORT
#      if (STM32WLXX_CRYPTO_TRNG_SUPPORT != DISABLED)
#        define CUBICRYPT_HAVE_CYCLONE_TRNG
#      endif
#    endif
#  endif
#endif
