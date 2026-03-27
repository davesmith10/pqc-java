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

} // extern "C"
