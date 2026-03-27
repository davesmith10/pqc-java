#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
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

static int test_ec_kem_roundtrip(const char *alg,
                                  size_t pk_len, size_t sk_len,
                                  size_t ct_len, size_t ss_len) {
    uint8_t pk[133], sk[66], ct[133], ss_enc[66], ss_dec[66];

    assert(crystals_ffi_ec_kem_pk_bytes(alg) == pk_len);
    assert(crystals_ffi_ec_kem_sk_bytes(alg) == sk_len);
    assert(crystals_ffi_ec_kem_ct_bytes(alg) == ct_len);

    assert(crystals_ffi_ec_kem_keygen(alg, pk, pk_len, sk, sk_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_ec_kem_encaps(alg, pk, pk_len,
                                       ct, ct_len, ss_enc, ss_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_ec_kem_decaps(alg, sk, sk_len,
                                       ct, ct_len, ss_dec, ss_len) == CRYSTALS_FFI_OK);
    assert(memcmp(ss_enc, ss_dec, ss_len) == 0);
    return 0;
}

static int test_ec_kem_roundtrips(void) {
    assert(test_ec_kem_roundtrip("X25519",  32,  32, 32, 32) == 0);
    assert(test_ec_kem_roundtrip("P-256",   65,  32, 65, 32) == 0);
    assert(test_ec_kem_roundtrip("P-384",   97,  48, 97, 48) == 0);
    assert(test_ec_kem_roundtrip("P-521",  133,  66, 133, 66) == 0);
    return 0;
}

static int test_ec_sig_roundtrip(const char *alg,
                                  size_t pk_len, size_t sk_len, size_t sig_len) {
    uint8_t pk[133], sk[66], sig[132];
    const uint8_t msg[]     = "sign this message";
    const uint8_t bad_msg[] = "sign THIS message";
    size_t msg_len = sizeof(msg) - 1;

    assert(crystals_ffi_ec_sig_pk_bytes(alg) == pk_len);
    assert(crystals_ffi_ec_sig_sk_bytes(alg) == sk_len);
    assert(crystals_ffi_ec_sig_bytes(alg)    == sig_len);

    assert(crystals_ffi_ec_sig_keygen(alg, pk, pk_len, sk, sk_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_ec_sig_sign(alg, sk, sk_len, msg, msg_len,
                                     sig, sig_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_ec_sig_verify(alg, pk, pk_len, msg, msg_len,
                                       sig, sig_len) == CRYSTALS_FFI_OK);

    /* tampered message → ECRYPTO */
    assert(crystals_ffi_ec_sig_verify(alg, pk, pk_len, bad_msg, msg_len,
                                       sig, sig_len) == CRYSTALS_FFI_ECRYPTO);
    return 0;
}

static int test_ec_sig_roundtrips(void) {
    assert(test_ec_sig_roundtrip("Ed25519",     32, 32, 64)  == 0);
    assert(test_ec_sig_roundtrip("ECDSA P-256", 65, 32, 64)  == 0);
    assert(test_ec_sig_roundtrip("ECDSA P-384", 97, 48, 96)  == 0);
    assert(test_ec_sig_roundtrip("ECDSA P-521", 133,66, 132) == 0);
    return 0;
}

static int test_mceliece_sizes(void) {
    assert(crystals_ffi_mceliece_pk_bytes("mceliece348864f")  ==   261120);
    assert(crystals_ffi_mceliece_pk_bytes("mceliece460896f")  ==   524160);
    assert(crystals_ffi_mceliece_pk_bytes("mceliece6688128f") ==  1044992);
    assert(crystals_ffi_mceliece_pk_bytes("mceliece6960119f") ==  1047319);
    assert(crystals_ffi_mceliece_pk_bytes("mceliece8192128f") ==  1357824);

    assert(crystals_ffi_mceliece_sk_bytes("mceliece348864f")  ==     6492);
    assert(crystals_ffi_mceliece_sk_bytes("mceliece460896f")  ==    13608);
    assert(crystals_ffi_mceliece_sk_bytes("mceliece6688128f") ==    13932);
    assert(crystals_ffi_mceliece_sk_bytes("mceliece6960119f") ==    13948);
    assert(crystals_ffi_mceliece_sk_bytes("mceliece8192128f") ==    14120);

    assert(crystals_ffi_mceliece_ct_bytes("mceliece348864f")  ==       96);
    assert(crystals_ffi_mceliece_ct_bytes("mceliece460896f")  ==      156);
    assert(crystals_ffi_mceliece_ct_bytes("mceliece6688128f") ==      208);
    assert(crystals_ffi_mceliece_ct_bytes("mceliece6960119f") ==      194);
    assert(crystals_ffi_mceliece_ct_bytes("mceliece8192128f") ==      208);

    assert(CRYSTALS_FFI_MCELIECE_SS_BYTES == 32);

    assert(crystals_ffi_mceliece_pk_bytes("bad") == 0);
    assert(crystals_ffi_mceliece_sk_bytes(NULL)  == 0);
    return 0;
}

/* Roundtrip only the smallest variant — larger ones take too long for a unit test */
static int test_mceliece_roundtrip(void) {
    const char *ps = "mceliece348864f";
    size_t pk_len = crystals_ffi_mceliece_pk_bytes(ps);
    size_t sk_len = crystals_ffi_mceliece_sk_bytes(ps);
    size_t ct_len = crystals_ffi_mceliece_ct_bytes(ps);
    size_t ss_len = CRYSTALS_FFI_MCELIECE_SS_BYTES;

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t *ct = malloc(ct_len);
    uint8_t ss_enc[32], ss_dec[32];

    assert(crystals_ffi_mceliece_keygen(ps, pk, pk_len, sk, sk_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_mceliece_encaps(ps, pk, pk_len, ct, ct_len,
                                         ss_enc, ss_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_mceliece_decaps(ps, sk, sk_len, ct, ct_len,
                                         ss_dec, ss_len) == CRYSTALS_FFI_OK);
    assert(memcmp(ss_enc, ss_dec, ss_len) == 0);

    free(pk); free(sk); free(ct);
    return 0;
}

static int test_slhdsa_roundtrip(const char *alg,
                                  size_t pk_len, size_t sk_len, size_t sig_len) {
    const uint8_t msg[]     = "hello post-quantum world";
    const uint8_t bad_msg[] = "hello post-quantum WORLD";
    size_t msg_len = sizeof(msg) - 1;

    uint8_t *pk  = malloc(pk_len);
    uint8_t *sk  = malloc(sk_len);
    uint8_t *sig = malloc(sig_len);

    assert(crystals_ffi_slhdsa_pk_bytes(alg) == pk_len);
    assert(crystals_ffi_slhdsa_sk_bytes(alg) == sk_len);
    assert(crystals_ffi_slhdsa_sig_bytes(alg) == sig_len);

    assert(crystals_ffi_slhdsa_keygen(alg, pk, pk_len, sk, sk_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_slhdsa_sign(alg, sk, sk_len, msg, msg_len,
                                     sig, sig_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_slhdsa_verify(alg, pk, pk_len, msg, msg_len,
                                       sig, sig_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_slhdsa_verify(alg, pk, pk_len, bad_msg, msg_len,
                                       sig, sig_len) == CRYSTALS_FFI_ECRYPTO);
    free(pk); free(sk); free(sig);
    return 0;
}

static int test_slhdsa_roundtrips(void) {
    assert(test_slhdsa_roundtrip("SLH-DSA-SHA2-128f",   32,  64, 17088) == 0);
    assert(test_slhdsa_roundtrip("SLH-DSA-SHA2-192f",   48,  96, 35664) == 0);
    assert(test_slhdsa_roundtrip("SLH-DSA-SHAKE-192f",  48,  96, 35664) == 0);
    assert(test_slhdsa_roundtrip("SLH-DSA-SHA2-256f",   64, 128, 49856) == 0);
    assert(test_slhdsa_roundtrip("SLH-DSA-SHAKE-256f",  64, 128, 49856) == 0);
    return 0;
}

static int test_oqs_kem_roundtrip(const char *alg,
                                   size_t pk_len, size_t sk_len,
                                   size_t ct_len, size_t ss_len) {
    uint8_t *pk    = malloc(pk_len);
    uint8_t *sk    = malloc(sk_len);
    uint8_t *ct    = malloc(ct_len);
    uint8_t *ss_e  = malloc(ss_len);
    uint8_t *ss_d  = malloc(ss_len);

    assert(crystals_ffi_oqs_kem_pk_bytes(alg) == pk_len);
    assert(crystals_ffi_oqs_kem_sk_bytes(alg) == sk_len);
    assert(crystals_ffi_oqs_kem_ct_bytes(alg) == ct_len);
    assert(crystals_ffi_oqs_kem_ss_bytes(alg) == ss_len);

    assert(crystals_ffi_oqs_kem_keygen(alg, pk, pk_len, sk, sk_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_oqs_kem_encaps(alg, pk, pk_len,
                                        ct, ct_len, ss_e, ss_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_oqs_kem_decaps(alg, sk, sk_len,
                                        ct, ct_len, ss_d, ss_len) == CRYSTALS_FFI_OK);
    assert(memcmp(ss_e, ss_d, ss_len) == 0);

    free(pk); free(sk); free(ct); free(ss_e); free(ss_d);
    return 0;
}

static int test_oqs_kem_roundtrips(void) {
    assert(test_oqs_kem_roundtrip("ML-KEM-512",         800,   1632,    768, 32) == 0);
    assert(test_oqs_kem_roundtrip("ML-KEM-768",        1184,   2400,   1088, 32) == 0);
    assert(test_oqs_kem_roundtrip("ML-KEM-1024",       1568,   3168,   1568, 32) == 0);
    assert(test_oqs_kem_roundtrip("FrodoKEM-640-AES",  9616,  19888,   9752, 16) == 0);
    assert(test_oqs_kem_roundtrip("FrodoKEM-976-AES", 15632,  31296,  15792, 24) == 0);
    assert(test_oqs_kem_roundtrip("FrodoKEM-1344-AES",21520,  43088,  21696, 32) == 0);
    return 0;
}

static int test_oqs_sig_roundtrip(const char *alg,
                                   size_t pk_len, size_t sk_len, size_t sig_max) {
    const uint8_t msg[]     = "hello post-quantum world";
    const uint8_t bad_msg[] = "hello post-quantum WORLD";
    size_t msg_len = sizeof(msg) - 1;

    uint8_t *pk  = malloc(pk_len);
    uint8_t *sk  = malloc(sk_len);
    uint8_t *sig = malloc(sig_max);
    size_t   actual_sig_len = 0;

    assert(crystals_ffi_oqs_sig_pk_bytes(alg) == pk_len);
    assert(crystals_ffi_oqs_sig_sk_bytes(alg) == sk_len);
    assert(crystals_ffi_oqs_sig_bytes(alg)    == sig_max);

    assert(crystals_ffi_oqs_sig_keygen(alg, pk, pk_len, sk, sk_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_oqs_sig_sign(alg, sk, sk_len, msg, msg_len,
                                      sig, sig_max, &actual_sig_len) == CRYSTALS_FFI_OK);
    assert(actual_sig_len > 0 && actual_sig_len <= sig_max);

    assert(crystals_ffi_oqs_sig_verify(alg, pk, pk_len, msg, msg_len,
                                        sig, actual_sig_len) == CRYSTALS_FFI_OK);
    assert(crystals_ffi_oqs_sig_verify(alg, pk, pk_len, bad_msg, msg_len,
                                        sig, actual_sig_len) == CRYSTALS_FFI_ECRYPTO);
    free(pk); free(sk); free(sig);
    return 0;
}

static int test_oqs_sig_roundtrips(void) {
    assert(test_oqs_sig_roundtrip("ML-DSA-44",    1312, 2560, 2420) == 0);
    assert(test_oqs_sig_roundtrip("ML-DSA-65",    1952, 4032, 3309) == 0);
    assert(test_oqs_sig_roundtrip("ML-DSA-87",    2592, 4896, 4627) == 0);
    assert(test_oqs_sig_roundtrip("Falcon-512",    897, 1281,  752) == 0);
    assert(test_oqs_sig_roundtrip("Falcon-1024",  1793, 2305, 1462) == 0);
    return 0;
}

int main(void) {
    RUN(kyber_sizes);
    RUN(dilithium_sizes);
    RUN(kyber_keygen);
    RUN(kyber_roundtrips);
    RUN(dilithium_roundtrips);
    RUN(ec_kem_roundtrips);
    RUN(ec_sig_roundtrips);
    RUN(mceliece_sizes);
    RUN(mceliece_roundtrip);
    RUN(slhdsa_roundtrips);
    RUN(oqs_kem_roundtrips);
    RUN(oqs_sig_roundtrips);
    return tests_failed;
}
