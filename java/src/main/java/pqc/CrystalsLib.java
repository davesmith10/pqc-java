package pqc;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Path;

/**
 * Package-private FFM bootstrap: loads libcrystals_ffi.so and wires all 24 native
 * method handles. Consumed only by the public API classes in this package.
 */
final class CrystalsLib {

    private static final SymbolLookup LIB;
    private static final Linker       LINKER = Linker.nativeLinker();

    static {
        String path = System.getProperty("crystals.ffi.lib",
            "shim/build/libcrystals_ffi.so");
        LIB = SymbolLookup.libraryLookup(Path.of(path), Arena.global());
    }

    // ── Layout aliases ────────────────────────────────────────────────────────
    static final ValueLayout.OfInt  INT  = ValueLayout.JAVA_INT;
    static final ValueLayout.OfLong LONG = ValueLayout.JAVA_LONG;  // size_t on 64-bit
    static final AddressLayout      ADDR = ValueLayout.ADDRESS;

    // ── Return codes (mirror C #defines) ─────────────────────────────────────
    static final int OK       =  0;
    static final int EARG     = -1;
    static final int ECRYPTO  = -2;
    // EUNKNOWN = -3 (any other value)

    // ── Helper ────────────────────────────────────────────────────────────────
    private static MethodHandle mh(String sym, FunctionDescriptor fd) {
        return LINKER.downcallHandle(
            LIB.find(sym).orElseThrow(() ->
                new UnsatisfiedLinkError("symbol not found: " + sym)),
            fd);
    }

    static void checkResult(int rc, String fn) {
        switch (rc) {
            case OK    -> {}
            case EARG  -> throw new IllegalArgumentException(fn + ": bad argument");
            default    -> throw new CrystalsException(fn + ": error code " + rc);
        }
    }

    // ── Kyber ─────────────────────────────────────────────────────────────────
    static final MethodHandle KYBER_PK_BYTES = mh("crystals_ffi_kyber_pk_bytes",
        FunctionDescriptor.of(LONG, INT));
    static final MethodHandle KYBER_SK_BYTES = mh("crystals_ffi_kyber_sk_bytes",
        FunctionDescriptor.of(LONG, INT));
    static final MethodHandle KYBER_CT_BYTES = mh("crystals_ffi_kyber_ct_bytes",
        FunctionDescriptor.of(LONG, INT));
    static final MethodHandle KYBER_KEYGEN = mh("crystals_ffi_kyber_keygen",
        FunctionDescriptor.of(INT, INT, ADDR, LONG, ADDR, LONG));
    static final MethodHandle KYBER_ENCAPS = mh("crystals_ffi_kyber_encaps",
        FunctionDescriptor.of(INT, INT, ADDR, LONG, ADDR, LONG, ADDR, LONG));
    static final MethodHandle KYBER_DECAPS = mh("crystals_ffi_kyber_decaps",
        FunctionDescriptor.of(INT, INT, ADDR, LONG, ADDR, LONG, ADDR, LONG));

    // ── Dilithium ─────────────────────────────────────────────────────────────
    static final MethodHandle DILITHIUM_PK_BYTES = mh("crystals_ffi_dilithium_pk_bytes",
        FunctionDescriptor.of(LONG, INT));
    static final MethodHandle DILITHIUM_SK_BYTES = mh("crystals_ffi_dilithium_sk_bytes",
        FunctionDescriptor.of(LONG, INT));
    static final MethodHandle DILITHIUM_SIG_BYTES = mh("crystals_ffi_dilithium_sig_bytes",
        FunctionDescriptor.of(LONG, INT));
    static final MethodHandle DILITHIUM_KEYGEN = mh("crystals_ffi_dilithium_keygen",
        FunctionDescriptor.of(INT, INT, ADDR, LONG, ADDR, LONG));
    static final MethodHandle DILITHIUM_SIGN = mh("crystals_ffi_dilithium_sign",
        FunctionDescriptor.of(INT, INT, ADDR, LONG, ADDR, LONG, ADDR, LONG));
    static final MethodHandle DILITHIUM_VERIFY = mh("crystals_ffi_dilithium_verify",
        FunctionDescriptor.of(INT, INT, ADDR, LONG, ADDR, LONG, ADDR, LONG));

    // ── EC KEM ────────────────────────────────────────────────────────────────
    static final MethodHandle EC_KEM_PK_BYTES = mh("crystals_ffi_ec_kem_pk_bytes",
        FunctionDescriptor.of(LONG, ADDR));
    static final MethodHandle EC_KEM_SK_BYTES = mh("crystals_ffi_ec_kem_sk_bytes",
        FunctionDescriptor.of(LONG, ADDR));
    static final MethodHandle EC_KEM_CT_BYTES = mh("crystals_ffi_ec_kem_ct_bytes",
        FunctionDescriptor.of(LONG, ADDR));
    static final MethodHandle EC_KEM_KEYGEN = mh("crystals_ffi_ec_kem_keygen",
        FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG));
    static final MethodHandle EC_KEM_ENCAPS = mh("crystals_ffi_ec_kem_encaps",
        FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG, ADDR, LONG));
    static final MethodHandle EC_KEM_DECAPS = mh("crystals_ffi_ec_kem_decaps",
        FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG, ADDR, LONG));

    // ── EC Sig ────────────────────────────────────────────────────────────────
    static final MethodHandle EC_SIG_PK_BYTES = mh("crystals_ffi_ec_sig_pk_bytes",
        FunctionDescriptor.of(LONG, ADDR));
    static final MethodHandle EC_SIG_SK_BYTES = mh("crystals_ffi_ec_sig_sk_bytes",
        FunctionDescriptor.of(LONG, ADDR));
    static final MethodHandle EC_SIG_BYTES = mh("crystals_ffi_ec_sig_bytes",
        FunctionDescriptor.of(LONG, ADDR));
    static final MethodHandle EC_SIG_KEYGEN = mh("crystals_ffi_ec_sig_keygen",
        FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG));
    static final MethodHandle EC_SIG_SIGN = mh("crystals_ffi_ec_sig_sign",
        FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG, ADDR, LONG));
    static final MethodHandle EC_SIG_VERIFY = mh("crystals_ffi_ec_sig_verify",
        FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG, ADDR, LONG));

    // ── McEliece KEM ──────────────────────────────────────────────────────────────
    static final int MCELIECE_SS_BYTES = 32;
    static final MethodHandle MCELIECE_PK_BYTES = mh("crystals_ffi_mceliece_pk_bytes",
        FunctionDescriptor.of(LONG, ADDR));
    static final MethodHandle MCELIECE_SK_BYTES = mh("crystals_ffi_mceliece_sk_bytes",
        FunctionDescriptor.of(LONG, ADDR));
    static final MethodHandle MCELIECE_CT_BYTES = mh("crystals_ffi_mceliece_ct_bytes",
        FunctionDescriptor.of(LONG, ADDR));
    static final MethodHandle MCELIECE_KEYGEN = mh("crystals_ffi_mceliece_keygen",
        FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG));
    static final MethodHandle MCELIECE_ENCAPS = mh("crystals_ffi_mceliece_encaps",
        FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG, ADDR, LONG));
    static final MethodHandle MCELIECE_DECAPS = mh("crystals_ffi_mceliece_decaps",
        FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG, ADDR, LONG));

    private CrystalsLib() {}
}
