#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include "crystals_ffi.h"

static int tests_failed = 0;

#define RUN(name) \
    do { int _r = test_##name(); \
         if (_r) { printf("FAIL: " #name "\n"); tests_failed++; } \
         else    { printf("PASS: " #name "\n"); } \
    } while (0)

static int test_kyber_sizes(void) {
    assert(crystals_ffi_kyber_pk_bytes(512)  == 800);
    assert(crystals_ffi_kyber_pk_bytes(768)  == 1184);
    assert(crystals_ffi_kyber_pk_bytes(1024) == 1568);
    assert(crystals_ffi_kyber_sk_bytes(512)  == 1632);
    assert(crystals_ffi_kyber_sk_bytes(768)  == 2400);
    assert(crystals_ffi_kyber_sk_bytes(1024) == 3168);
    assert(crystals_ffi_kyber_ct_bytes(512)  == 768);
    assert(crystals_ffi_kyber_ct_bytes(768)  == 1088);
    assert(crystals_ffi_kyber_ct_bytes(1024) == 1568);
    assert(CRYSTALS_FFI_KYBER_SS_BYTES == 32);
    return 0;
}

static int test_dilithium_sizes(void) {
    assert(crystals_ffi_dilithium_pk_bytes(2) == 1312);
    assert(crystals_ffi_dilithium_pk_bytes(3) == 1952);
    assert(crystals_ffi_dilithium_pk_bytes(5) == 2592);
    assert(crystals_ffi_dilithium_sk_bytes(2) == 2560);
    assert(crystals_ffi_dilithium_sk_bytes(3) == 4032);
    assert(crystals_ffi_dilithium_sk_bytes(5) == 4896);
    assert(crystals_ffi_dilithium_sig_bytes(2) == 2420);
    assert(crystals_ffi_dilithium_sig_bytes(3) == 3309);
    assert(crystals_ffi_dilithium_sig_bytes(5) == 4627);
    return 0;
}

static int test_kyber_keygen(void) {
    uint8_t pk[1568], sk[3168]; /* max sizes (level 1024) */

    assert(crystals_ffi_kyber_keygen(512,  pk, 800,  sk, 1632) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_kyber_keygen(768,  pk, 1184, sk, 2400) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_kyber_keygen(1024, pk, 1568, sk, 3168) == CRYSTALS_FFI_OK);

    /* invalid level → EARG */
    assert(crystals_ffi_kyber_keygen(999, pk, 800, sk, 1632) == CRYSTALS_FFI_EARG);

    /* buffer too small → EARG */
    assert(crystals_ffi_kyber_keygen(512, pk, 10, sk, 1632) == CRYSTALS_FFI_EARG);
    return 0;
}

static int test_kyber_roundtrip(int level) {
    size_t pk_len = crystals_ffi_kyber_pk_bytes(level);
    size_t sk_len = crystals_ffi_kyber_sk_bytes(level);
    size_t ct_len = crystals_ffi_kyber_ct_bytes(level);

    uint8_t pk[1568], sk[3168], ct[1568];
    uint8_t ss_enc[32], ss_dec[32];

    assert(crystals_ffi_kyber_keygen(level, pk, pk_len, sk, sk_len) == CRYSTALS_FFI_OK);

    assert(crystals_ffi_kyber_encaps(level,
                                      pk, pk_len,
                                      ct, ct_len,
                                      ss_enc, CRYSTALS_FFI_KYBER_SS_BYTES)
           == CRYSTALS_FFI_OK);

    assert(crystals_ffi_kyber_decaps(level,
                                      sk, sk_len,
                                      ct, ct_len,
                                      ss_dec, CRYSTALS_FFI_KYBER_SS_BYTES)
           == CRYSTALS_FFI_OK);

    assert(memcmp(ss_enc, ss_dec, 32) == 0);  /* shared secrets must match */
    return 0;
}

static int test_kyber_roundtrips(void) {
    assert(test_kyber_roundtrip(512)  == 0);
    assert(test_kyber_roundtrip(768)  == 0);
    assert(test_kyber_roundtrip(1024) == 0);
    return 0;
}

static int test_dilithium_roundtrip(int mode) {
    size_t pk_len  = crystals_ffi_dilithium_pk_bytes(mode);
    size_t sk_len  = crystals_ffi_dilithium_sk_bytes(mode);
    size_t sig_max = crystals_ffi_dilithium_sig_bytes(mode);

    uint8_t pk[2592], sk[4896], sig[4627];
    const uint8_t msg[]     = "hello post-quantum world";
    const uint8_t bad_msg[] = "hello post-quantum WORLD"; /* same length, different content */
    size_t msg_len = sizeof(msg) - 1;

    assert(crystals_ffi_dilithium_keygen(mode, pk, pk_len, sk, sk_len)
           == CRYSTALS_FFI_OK);

    assert(crystals_ffi_dilithium_sign(mode, sk, sk_len, msg, msg_len, sig, sig_max)
           == CRYSTALS_FFI_OK);

    /* valid sig → OK */
    assert(crystals_ffi_dilithium_verify(mode, pk, pk_len, msg, msg_len, sig, sig_max)
           == CRYSTALS_FFI_OK);

    /* tampered message → ECRYPTO */
    assert(crystals_ffi_dilithium_verify(mode, pk, pk_len, bad_msg, msg_len, sig, sig_max)
           == CRYSTALS_FFI_ECRYPTO);
    return 0;
}

static int test_dilithium_roundtrips(void) {
    assert(test_dilithium_roundtrip(2) == 0);
    assert(test_dilithium_roundtrip(3) == 0);
    assert(test_dilithium_roundtrip(5) == 0);
    return 0;
}

int main(void) {
    RUN(kyber_sizes);
    RUN(dilithium_sizes);
    RUN(kyber_keygen);
    RUN(kyber_roundtrips);
    RUN(dilithium_roundtrips);
    return tests_failed;
}
