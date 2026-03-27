#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────── */
#define CRYSTALS_FFI_KYBER_SS_BYTES  32

/* ── Return codes ───────────────────────────────────────── */
#define CRYSTALS_FFI_OK       0
#define CRYSTALS_FFI_EARG    -1   /* bad level/mode, NULL ptr, or buffer too small */
#define CRYSTALS_FFI_ECRYPTO -2   /* crypto failure (verify mismatch, keygen fail) */
#define CRYSTALS_FFI_EUNKNOWN -3  /* unexpected C++ exception */

/* ── Size queries (return 0 for unknown level/mode) ────── */
size_t crystals_ffi_kyber_pk_bytes(int level);
size_t crystals_ffi_kyber_sk_bytes(int level);
size_t crystals_ffi_kyber_ct_bytes(int level);

size_t crystals_ffi_dilithium_pk_bytes(int mode);
size_t crystals_ffi_dilithium_sk_bytes(int mode);
size_t crystals_ffi_dilithium_sig_bytes(int mode);

/* ── Kyber KEM ─────────────────────────────────────────── */
int crystals_ffi_kyber_keygen(int level,
                               uint8_t *pk_out, size_t pk_len,
                               uint8_t *sk_out, size_t sk_len);

int crystals_ffi_kyber_encaps(int level,
                               const uint8_t *pk,     size_t pk_len,
                               uint8_t       *ct_out, size_t ct_len,
                               uint8_t       *ss_out, size_t ss_len);

int crystals_ffi_kyber_decaps(int level,
                               const uint8_t *sk,     size_t sk_len,
                               const uint8_t *ct,     size_t ct_len,
                               uint8_t       *ss_out, size_t ss_len);

/* ── Dilithium signatures ──────────────────────────────── */
int crystals_ffi_dilithium_keygen(int mode,
                                   uint8_t *pk_out, size_t pk_len,
                                   uint8_t *sk_out, size_t sk_len);

int crystals_ffi_dilithium_sign(int mode,
                                 const uint8_t *sk,      size_t sk_len,
                                 const uint8_t *msg,     size_t msg_len,
                                 uint8_t       *sig_out, size_t sig_len);

int crystals_ffi_dilithium_verify(int mode,
                                   const uint8_t *pk,  size_t pk_len,
                                   const uint8_t *msg, size_t msg_len,
                                   const uint8_t *sig, size_t sig_len);

/* ── EC KEM (alg_name: "X25519" | "P-256" | "P-384" | "P-521") ── */
size_t crystals_ffi_ec_kem_pk_bytes(const char *alg_name);
size_t crystals_ffi_ec_kem_sk_bytes(const char *alg_name);
size_t crystals_ffi_ec_kem_ct_bytes(const char *alg_name); /* ct = ephemeral pk */

int crystals_ffi_ec_kem_keygen(const char *alg_name,
                                uint8_t *pk_out, size_t pk_len,
                                uint8_t *sk_out, size_t sk_len);

int crystals_ffi_ec_kem_encaps(const char *alg_name,
                                const uint8_t *pk,     size_t pk_len,
                                uint8_t       *ct_out, size_t ct_len,
                                uint8_t       *ss_out, size_t ss_len);

int crystals_ffi_ec_kem_decaps(const char *alg_name,
                                const uint8_t *sk,     size_t sk_len,
                                const uint8_t *ct,     size_t ct_len,
                                uint8_t       *ss_out, size_t ss_len);

/* ── EC signatures (alg_name: "Ed25519" | "ECDSA P-256" | "ECDSA P-384" | "ECDSA P-521") ── */
size_t crystals_ffi_ec_sig_pk_bytes(const char *alg_name);
size_t crystals_ffi_ec_sig_sk_bytes(const char *alg_name);
size_t crystals_ffi_ec_sig_bytes(const char *alg_name);

int crystals_ffi_ec_sig_keygen(const char *alg_name,
                                uint8_t *pk_out, size_t pk_len,
                                uint8_t *sk_out, size_t sk_len);

int crystals_ffi_ec_sig_sign(const char *alg_name,
                              const uint8_t *sk,      size_t sk_len,
                              const uint8_t *msg,     size_t msg_len,
                              uint8_t       *sig_out, size_t sig_len);

int crystals_ffi_ec_sig_verify(const char *alg_name,
                                const uint8_t *pk,  size_t pk_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len);

#define CRYSTALS_FFI_MCELIECE_SS_BYTES 32

/* ── McEliece KEM (param_set: "mceliece348864f" | "mceliece460896f" |
                              "mceliece6688128f" | "mceliece6960119f" |
                              "mceliece8192128f") ── */
size_t crystals_ffi_mceliece_pk_bytes(const char *param_set);
size_t crystals_ffi_mceliece_sk_bytes(const char *param_set);
size_t crystals_ffi_mceliece_ct_bytes(const char *param_set);

int crystals_ffi_mceliece_keygen(const char *param_set,
                                  uint8_t *pk_out, size_t pk_len,
                                  uint8_t *sk_out, size_t sk_len);

int crystals_ffi_mceliece_encaps(const char *param_set,
                                  const uint8_t *pk,     size_t pk_len,
                                  uint8_t       *ct_out, size_t ct_len,
                                  uint8_t       *ss_out, size_t ss_len);

int crystals_ffi_mceliece_decaps(const char *param_set,
                                  const uint8_t *sk,     size_t sk_len,
                                  const uint8_t *ct,     size_t ct_len,
                                  uint8_t       *ss_out, size_t ss_len);

/* ── SLH-DSA signatures (alg_name: "SLH-DSA-SHA2-128f" | "SLH-DSA-SHA2-192f" |
                                    "SLH-DSA-SHAKE-192f" | "SLH-DSA-SHA2-256f" |
                                    "SLH-DSA-SHAKE-256f") ── */
size_t crystals_ffi_slhdsa_pk_bytes(const char *alg_name);
size_t crystals_ffi_slhdsa_sk_bytes(const char *alg_name);
size_t crystals_ffi_slhdsa_sig_bytes(const char *alg_name);

int crystals_ffi_slhdsa_keygen(const char *alg_name,
                                uint8_t *pk_out, size_t pk_len,
                                uint8_t *sk_out, size_t sk_len);

int crystals_ffi_slhdsa_sign(const char *alg_name,
                              const uint8_t *sk,      size_t sk_len,
                              const uint8_t *msg,     size_t msg_len,
                              uint8_t       *sig_out, size_t sig_len);

int crystals_ffi_slhdsa_verify(const char *alg_name,
                                const uint8_t *pk,  size_t pk_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len);

/* ── OQS KEM (alg_name: "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024" |
                         "FrodoKEM-640-AES" | "FrodoKEM-976-AES" |
                         "FrodoKEM-1344-AES") ── */
size_t crystals_ffi_oqs_kem_pk_bytes(const char *alg_name);
size_t crystals_ffi_oqs_kem_sk_bytes(const char *alg_name);
size_t crystals_ffi_oqs_kem_ct_bytes(const char *alg_name);
size_t crystals_ffi_oqs_kem_ss_bytes(const char *alg_name);

int crystals_ffi_oqs_kem_keygen(const char *alg_name,
                                  uint8_t *pk_out, size_t pk_len,
                                  uint8_t *sk_out, size_t sk_len);

int crystals_ffi_oqs_kem_encaps(const char *alg_name,
                                  const uint8_t *pk,     size_t pk_len,
                                  uint8_t       *ct_out, size_t ct_len,
                                  uint8_t       *ss_out, size_t ss_len);

int crystals_ffi_oqs_kem_decaps(const char *alg_name,
                                  const uint8_t *sk,     size_t sk_len,
                                  const uint8_t *ct,     size_t ct_len,
                                  uint8_t       *ss_out, size_t ss_len);

#ifdef __cplusplus
}
#endif
