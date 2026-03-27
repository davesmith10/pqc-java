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

#ifdef __cplusplus
}
#endif
