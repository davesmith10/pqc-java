#include "crystals_ffi.h"
#include <crystals/crystals.hpp>
#include <cstring>
#include <vector>
#include <stdexcept>

// Static EC KEM helper functions (outside extern "C")
static ec::Algorithm kem_alg(const char *name) {
    if (!name) throw std::invalid_argument("null alg_name");
    std::string s(name);
    if (s == "X25519") return ec::Algorithm::X25519;
    if (s == "P-256")  return ec::Algorithm::P256;
    if (s == "P-384")  return ec::Algorithm::P384;
    if (s == "P-521")  return ec::Algorithm::P521;
    throw std::invalid_argument("unknown EC KEM alg: " + s);
}

static size_t ec_kem_pk_sz(const char *n) {
    if (!n) return 0;
    std::string s(n);
    if (s=="X25519") return 32;
    if (s=="P-256")  return 65;
    if (s=="P-384")  return 97;
    if (s=="P-521")  return 133;
    return 0;
}

static size_t ec_kem_sk_sz(const char *n) {
    if (!n) return 0;
    std::string s(n);
    if (s=="X25519") return 32;
    if (s=="P-256")  return 32;
    if (s=="P-384")  return 48;
    if (s=="P-521")  return 66;
    return 0;
}

// Helper: map sig alg name to ec::Algorithm
static ec::Algorithm sig_alg(const char *name) {
    if (!name) throw std::invalid_argument("null alg_name");
    std::string s(name);
    if (s == "Ed25519")     return ec::Algorithm::Ed25519;
    if (s == "ECDSA P-256") return ec::Algorithm::P256;
    if (s == "ECDSA P-384") return ec::Algorithm::P384;
    if (s == "ECDSA P-521") return ec::Algorithm::P521;
    throw std::invalid_argument("unknown EC sig alg: " + s);
}

static size_t ec_sig_pk_sz(const char *n) {
    if (!n) return 0;
    std::string s(n);
    if (s=="Ed25519")     return 32;
    if (s=="ECDSA P-256") return 65;
    if (s=="ECDSA P-384") return 97;
    if (s=="ECDSA P-521") return 133;
    return 0;
}

static size_t ec_sig_sk_sz(const char *n) {
    if (!n) return 0;
    std::string s(n);
    if (s=="Ed25519")     return 32;
    if (s=="ECDSA P-256") return 32;
    if (s=="ECDSA P-384") return 48;
    if (s=="ECDSA P-521") return 66;
    return 0;
}

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

int crystals_ffi_dilithium_keygen(int mode,
                                   uint8_t *pk_out, size_t pk_len,
                                   uint8_t *sk_out, size_t sk_len)
{
    if (!pk_out || !sk_out) return CRYSTALS_FFI_EARG;
    try {
        auto szs = dilithium_sizes(mode);           // throws std::invalid_argument on bad mode
        if (pk_len < szs.pk_bytes || sk_len < szs.sk_bytes)
            return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> pk, sk;
        dilithium::keygen(mode, pk, sk);
        std::memcpy(pk_out, pk.data(), szs.pk_bytes);
        std::memcpy(sk_out, sk.data(), szs.sk_bytes);
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_dilithium_sign(int mode,
                                 const uint8_t *sk,      size_t sk_len,
                                 const uint8_t *msg,     size_t msg_len,
                                 uint8_t       *sig_out, size_t sig_len)
{
    if (!sk || !msg || !sig_out) return CRYSTALS_FFI_EARG;
    try {
        auto szs      = dilithium_sizes(mode);
        size_t sig_sz = dilithium_sig::sig_bytes_for_mode(mode);
        if (sk_len < szs.sk_bytes || sig_len < sig_sz)
            return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> sk_vec(sk,  sk  + szs.sk_bytes);
        std::vector<uint8_t> msg_vec(msg, msg + msg_len);
        std::vector<uint8_t> sig;
        dilithium_sig::sign(mode, sk_vec, msg_vec, sig);
        std::memcpy(sig_out, sig.data(), sig.size());
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_dilithium_verify(int mode,
                                   const uint8_t *pk,  size_t pk_len,
                                   const uint8_t *msg, size_t msg_len,
                                   const uint8_t *sig, size_t sig_len)
{
    if (!pk || !msg || !sig) return CRYSTALS_FFI_EARG;
    try {
        auto szs      = dilithium_sizes(mode);
        size_t sig_sz = dilithium_sig::sig_bytes_for_mode(mode);
        if (pk_len < szs.pk_bytes || sig_len < sig_sz)
            return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> pk_vec(pk,  pk  + szs.pk_bytes);
        std::vector<uint8_t> msg_vec(msg, msg + msg_len);
        std::vector<uint8_t> sig_vec(sig, sig + sig_sz);
        bool ok = dilithium_sig::verify(mode, pk_vec, msg_vec, sig_vec);
        return ok ? CRYSTALS_FFI_OK : CRYSTALS_FFI_ECRYPTO;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

size_t crystals_ffi_ec_kem_pk_bytes(const char *n) { return ec_kem_pk_sz(n); }
size_t crystals_ffi_ec_kem_sk_bytes(const char *n) { return ec_kem_sk_sz(n); }
size_t crystals_ffi_ec_kem_ct_bytes(const char *n) { return ec_kem_pk_sz(n); } /* ct = ephemeral pk */

int crystals_ffi_ec_kem_keygen(const char *alg_name,
                                uint8_t *pk_out, size_t pk_len,
                                uint8_t *sk_out, size_t sk_len)
{
    if (!alg_name || !pk_out || !sk_out) return CRYSTALS_FFI_EARG;
    try {
        auto alg = kem_alg(alg_name);
        if (pk_len < ec_kem_pk_sz(alg_name) || sk_len < ec_kem_sk_sz(alg_name))
            return CRYSTALS_FFI_EARG;
        auto kp = ec::keygen(alg);
        std::memcpy(pk_out, kp.pk.data(), kp.pk.size());
        std::memcpy(sk_out, kp.sk.data(), kp.sk.size());
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_ec_kem_encaps(const char *alg_name,
                                const uint8_t *pk,     size_t pk_len,
                                uint8_t       *ct_out, size_t ct_len,
                                uint8_t       *ss_out, size_t ss_len)
{
    if (!alg_name || !pk || !ct_out || !ss_out) return CRYSTALS_FFI_EARG;
    try {
        size_t expected_pk = ec_kem_pk_sz(alg_name);
        if (!expected_pk) return CRYSTALS_FFI_EARG;
        if (pk_len < expected_pk || ct_len < expected_pk) return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> pk_vec(pk, pk + expected_pk);
        std::vector<uint8_t> ct, ss;
        ec_kem::encaps(alg_name, pk_vec, ct, ss);
        std::memcpy(ct_out, ct.data(), ct.size());
        std::memcpy(ss_out, ss.data(), ss.size());
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_ec_kem_decaps(const char *alg_name,
                                const uint8_t *sk,     size_t sk_len,
                                const uint8_t *ct,     size_t ct_len,
                                uint8_t       *ss_out, size_t ss_len)
{
    if (!alg_name || !sk || !ct || !ss_out) return CRYSTALS_FFI_EARG;
    try {
        size_t expected_sk = ec_kem_sk_sz(alg_name);
        size_t expected_ct = ec_kem_pk_sz(alg_name); /* ct = ephemeral pk */
        if (!expected_sk || !expected_ct) return CRYSTALS_FFI_EARG;
        if (sk_len < expected_sk || ct_len < expected_ct) return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> sk_vec(sk, sk + expected_sk);
        std::vector<uint8_t> ct_vec(ct, ct + expected_ct);
        std::vector<uint8_t> ss;
        ec_kem::decaps(alg_name, sk_vec, ct_vec, ss);
        std::memcpy(ss_out, ss.data(), ss.size());
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

size_t crystals_ffi_ec_sig_pk_bytes(const char *n) { return ec_sig_pk_sz(n); }
size_t crystals_ffi_ec_sig_sk_bytes(const char *n) { return ec_sig_sk_sz(n); }
size_t crystals_ffi_ec_sig_bytes(const char *n) {
    try { return n ? ec_sig::sig_bytes(std::string(n)) : 0; }
    catch (...) { return 0; }
}

int crystals_ffi_ec_sig_keygen(const char *alg_name,
                                uint8_t *pk_out, size_t pk_len,
                                uint8_t *sk_out, size_t sk_len)
{
    if (!alg_name || !pk_out || !sk_out) return CRYSTALS_FFI_EARG;
    try {
        auto alg = sig_alg(alg_name);
        if (pk_len < ec_sig_pk_sz(alg_name) || sk_len < ec_sig_sk_sz(alg_name))
            return CRYSTALS_FFI_EARG;
        auto kp = ec::keygen(alg);
        std::memcpy(pk_out, kp.pk.data(), kp.pk.size());
        std::memcpy(sk_out, kp.sk.data(), kp.sk.size());
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_ec_sig_sign(const char *alg_name,
                              const uint8_t *sk,      size_t sk_len,
                              const uint8_t *msg,     size_t msg_len,
                              uint8_t       *sig_out, size_t sig_len)
{
    if (!alg_name || !sk || !msg || !sig_out) return CRYSTALS_FFI_EARG;
    try {
        std::string alg(alg_name);
        size_t expected_sk  = ec_sig_sk_sz(alg_name);
        size_t expected_sig = ec_sig::sig_bytes(alg);
        if (!expected_sk || !expected_sig) return CRYSTALS_FFI_EARG;
        if (sk_len < expected_sk || sig_len < expected_sig) return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> sk_vec(sk,  sk  + expected_sk);
        std::vector<uint8_t> msg_vec(msg, msg + msg_len);
        std::vector<uint8_t> sig;
        ec_sig::sign(alg, sk_vec, msg_vec, sig);
        std::memcpy(sig_out, sig.data(), sig.size());
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_ec_sig_verify(const char *alg_name,
                                const uint8_t *pk,  size_t pk_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len)
{
    if (!alg_name || !pk || !msg || !sig) return CRYSTALS_FFI_EARG;
    try {
        std::string alg(alg_name);
        size_t expected_pk  = ec_sig_pk_sz(alg_name);
        size_t expected_sig = ec_sig::sig_bytes(alg);
        if (!expected_pk || !expected_sig) return CRYSTALS_FFI_EARG;
        if (pk_len < expected_pk || sig_len < expected_sig) return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> pk_vec(pk,  pk  + expected_pk);
        std::vector<uint8_t> msg_vec(msg, msg + msg_len);
        std::vector<uint8_t> sig_vec(sig, sig + expected_sig);
        bool ok = ec_sig::verify(alg, pk_vec, msg_vec, sig_vec);
        return ok ? CRYSTALS_FFI_OK : CRYSTALS_FFI_ECRYPTO;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

} // extern "C"
