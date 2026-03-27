#include "crystals_ffi.h"
#include <crystals/crystals.hpp>
#include <cstring>

extern "C" {

size_t crystals_ffi_kyber_pk_bytes(int level) {
    try { return kyber_kem_sizes(level).pk_bytes; } catch (...) { return 0; }
}
size_t crystals_ffi_kyber_sk_bytes(int level) {
    try { return kyber_kem_sizes(level).sk_bytes; } catch (...) { return 0; }
}
size_t crystals_ffi_kyber_ct_bytes(int level) {
    try { return kyber_kem_sizes(level).ct_bytes; } catch (...) { return 0; }
}

size_t crystals_ffi_dilithium_pk_bytes(int mode) {
    try { return dilithium_sizes(mode).pk_bytes; } catch (...) { return 0; }
}
size_t crystals_ffi_dilithium_sk_bytes(int mode) {
    try { return dilithium_sizes(mode).sk_bytes; } catch (...) { return 0; }
}
size_t crystals_ffi_dilithium_sig_bytes(int mode) {
    try { return dilithium_sig::sig_bytes_for_mode(mode); } catch (...) { return 0; }
}

int crystals_ffi_kyber_keygen(int level,
                               uint8_t *pk_out, size_t pk_len,
                               uint8_t *sk_out, size_t sk_len)
{
    if (!pk_out || !sk_out) return CRYSTALS_FFI_EARG;
    try {
        auto szs = kyber_kem_sizes(level);          // throws std::invalid_argument on bad level
        if (pk_len < szs.pk_bytes || sk_len < szs.sk_bytes)
            return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> pk, sk;
        kyber::keygen(level, pk, sk);
        std::memcpy(pk_out, pk.data(), szs.pk_bytes);
        std::memcpy(sk_out, sk.data(), szs.sk_bytes);
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_kyber_encaps(int level,
                               const uint8_t *pk,     size_t pk_len,
                               uint8_t       *ct_out, size_t ct_len,
                               uint8_t       *ss_out, size_t ss_len)
{
    if (!pk || !ct_out || !ss_out) return CRYSTALS_FFI_EARG;
    try {
        auto szs = kyber_kem_sizes(level);
        if (pk_len < szs.pk_bytes || ct_len < szs.ct_bytes || ss_len < szs.ss_bytes)
            return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> pk_vec(pk, pk + szs.pk_bytes);
        std::vector<uint8_t> ct, ss;
        kyber_kem::encaps(level, pk_vec, ct, ss);
        std::memcpy(ct_out, ct.data(), szs.ct_bytes);
        std::memcpy(ss_out, ss.data(), szs.ss_bytes);
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_kyber_decaps(int level,
                               const uint8_t *sk,     size_t sk_len,
                               const uint8_t *ct,     size_t ct_len,
                               uint8_t       *ss_out, size_t ss_len)
{
    if (!sk || !ct || !ss_out) return CRYSTALS_FFI_EARG;
    try {
        auto szs = kyber_kem_sizes(level);
        if (sk_len < szs.sk_bytes || ct_len < szs.ct_bytes || ss_len < szs.ss_bytes)
            return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> sk_vec(sk, sk + szs.sk_bytes);
        std::vector<uint8_t> ct_vec(ct, ct + szs.ct_bytes);
        std::vector<uint8_t> ss;
        kyber_kem::decaps(level, sk_vec, ct_vec, ss);
        std::memcpy(ss_out, ss.data(), szs.ss_bytes);
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

} // extern "C"
