# Shim Full Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the C FFI shim and Java FFM bindings to cover all four libcrystals-1.2 profile groups — adding McEliece KEM, SLH-DSA, OQS KEM (ML-KEM + FrodoKEM), and OQS Sig (ML-DSA + Falcon).

**Architecture:** Each algorithm family gets its own block in the shim header + implementation, a block of MethodHandles in CrystalsLib.java, and a dedicated Java API class + JUnit 5 test. The OQS sig `sign` function adds an `actual_sig_len` out-parameter to handle Falcon's variable-length signatures correctly.

**Tech Stack:** C17 + C++17, libcrystals-1.2 (`Crystals::crystals` CMake target), Java 21 FFM, JUnit 5, Maven.

---

## Size Reference (hardcode these in the shim)

### McEliece KEM (from libmceliece headers; SS always 32)
| param_set | pk_bytes | sk_bytes | ct_bytes |
|---|---|---|---|
| mceliece348864f | 261120 | 6492 | 96 |
| mceliece460896f | 524160 | 13608 | 156 |
| mceliece6688128f | 1044992 | 13932 | 208 |
| mceliece6960119f | 1047319 | 13948 | 194 |
| mceliece8192128f | 1357824 | 14120 | 208 |

### SLH-DSA (pk/sk from SPHINCS+ standard; sig_bytes from slhdsa_sig.cpp)
| alg_name | pk_bytes | sk_bytes | sig_bytes |
|---|---|---|---|
| SLH-DSA-SHA2-128f | 32 | 64 | 17088 |
| SLH-DSA-SHA2-192f | 48 | 96 | 35664 |
| SLH-DSA-SHAKE-192f | 48 | 96 | 35664 |
| SLH-DSA-SHA2-256f | 64 | 128 | 49856 |
| SLH-DSA-SHAKE-256f | 64 | 128 | 49856 |

### OQS KEM — ML-KEM (from kem_ml_kem.h)
| alg_name | pk_bytes | sk_bytes | ct_bytes | ss_bytes |
|---|---|---|---|---|
| ML-KEM-512 | 800 | 1632 | 768 | 32 |
| ML-KEM-768 | 1184 | 2400 | 1088 | 32 |
| ML-KEM-1024 | 1568 | 3168 | 1568 | 32 |

### OQS KEM — FrodoKEM (from kem_frodokem.h)
| alg_name | pk_bytes | sk_bytes | ct_bytes | ss_bytes |
|---|---|---|---|---|
| FrodoKEM-640-AES | 9616 | 19888 | 9752 | 16 |
| FrodoKEM-976-AES | 15632 | 31296 | 15792 | 24 |
| FrodoKEM-1344-AES | 21520 | 43088 | 21696 | 32 |

### OQS Sig — ML-DSA (from sig_ml_dsa.h; fixed-length)
| alg_name | pk_bytes | sk_bytes | sig_bytes |
|---|---|---|---|
| ML-DSA-44 | 1312 | 2560 | 2420 |
| ML-DSA-65 | 1952 | 4032 | 3309 |
| ML-DSA-87 | 2592 | 4896 | 4627 |

### OQS Sig — Falcon (from sig_falcon.h; **variable-length**)
| alg_name | pk_bytes | sk_bytes | sig_bytes (MAX) |
|---|---|---|---|
| Falcon-512 | 897 | 1281 | 752 |
| Falcon-1024 | 1793 | 2305 | 1462 |

---

## File Map

**Modify:**
- `shim/include/crystals_ffi.h` — add 4 new function-family blocks
- `shim/src/crystals_ffi.cpp` — add static size tables + implementations
- `shim/test/test_shim.c` — add C tests (4 new test functions)
- `java/src/main/java/pqc/CrystalsLib.java` — add 25 new MethodHandles

**Create:**
- `java/src/main/java/pqc/McElieceKEM.java`
- `java/src/test/java/pqc/McElieceKEMTest.java`
- `java/src/main/java/pqc/SlhDsaSig.java`
- `java/src/test/java/pqc/SlhDsaTest.java`
- `java/src/main/java/pqc/OqsKEM.java`
- `java/src/test/java/pqc/OqsKEMTest.java`
- `java/src/main/java/pqc/OqsSig.java`
- `java/src/test/java/pqc/OqsSigTest.java`

---

## Task 1: McEliece KEM

**Files:**
- Modify: `shim/include/crystals_ffi.h`
- Modify: `shim/src/crystals_ffi.cpp`
- Modify: `shim/test/test_shim.c`
- Modify: `java/src/main/java/pqc/CrystalsLib.java`
- Create: `java/src/main/java/pqc/McElieceKEM.java`
- Create: `java/src/test/java/pqc/McElieceKEMTest.java`

- [ ] **Step 1: Write the failing C test**

Add to `shim/test/test_shim.c` (after the existing `test_ec_sig_roundtrips` function and before `main`):

```c
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
```

Add `RUN(mceliece_sizes);` and `RUN(mceliece_roundtrip);` to `main()`.

- [ ] **Step 2: Build — expect link failure (symbols undefined)**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc-java
cmake --build shim/build 2>&1 | grep -E "error:|undefined"
```
Expected: undefined reference to `crystals_ffi_mceliece_*`

- [ ] **Step 3: Add declarations to `shim/include/crystals_ffi.h`**

After the EC sig block, add:

```c
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
```

- [ ] **Step 4: Implement in `shim/src/crystals_ffi.cpp`**

Add static size helpers (outside `extern "C"`) after the existing `ec_sig_sk_sz` helper:

```cpp
struct McElieceSizes { size_t pk, sk, ct; };
static McElieceSizes mceliece_sz(const char *ps) {
    if (!ps) return {0,0,0};
    std::string s(ps);
    if (s=="mceliece348864f")  return { 261120,  6492,  96};
    if (s=="mceliece460896f")  return { 524160, 13608, 156};
    if (s=="mceliece6688128f") return {1044992, 13932, 208};
    if (s=="mceliece6960119f") return {1047319, 13948, 194};
    if (s=="mceliece8192128f") return {1357824, 14120, 208};
    return {0,0,0};
}
```

Inside `extern "C"`, add after the EC sig block:

```cpp
size_t crystals_ffi_mceliece_pk_bytes(const char *ps) { return mceliece_sz(ps).pk; }
size_t crystals_ffi_mceliece_sk_bytes(const char *ps) { return mceliece_sz(ps).sk; }
size_t crystals_ffi_mceliece_ct_bytes(const char *ps) { return mceliece_sz(ps).ct; }

int crystals_ffi_mceliece_keygen(const char *param_set,
                                  uint8_t *pk_out, size_t pk_len,
                                  uint8_t *sk_out, size_t sk_len)
{
    if (!param_set || !pk_out || !sk_out) return CRYSTALS_FFI_EARG;
    try {
        auto sz = mceliece_sz(param_set);
        if (!sz.pk || pk_len < sz.pk || sk_len < sz.sk) return CRYSTALS_FFI_EARG;
        auto keys = mcs::keygen_mceliece(std::string(param_set));
        std::memcpy(pk_out, keys.pk.data(), sz.pk);
        std::memcpy(sk_out, keys.sk.data(), sz.sk);
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_mceliece_encaps(const char *param_set,
                                  const uint8_t *pk,     size_t pk_len,
                                  uint8_t       *ct_out, size_t ct_len,
                                  uint8_t       *ss_out, size_t ss_len)
{
    if (!param_set || !pk || !ct_out || !ss_out) return CRYSTALS_FFI_EARG;
    try {
        auto sz = mceliece_sz(param_set);
        if (!sz.pk || pk_len < sz.pk || ct_len < sz.ct || ss_len < 32)
            return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> pk_vec(pk, pk + sz.pk), ct, ss;
        mceliece_kem::encaps(std::string(param_set), pk_vec, ct, ss);
        std::memcpy(ct_out, ct.data(), sz.ct);
        std::memcpy(ss_out, ss.data(), 32);
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_mceliece_decaps(const char *param_set,
                                  const uint8_t *sk,     size_t sk_len,
                                  const uint8_t *ct,     size_t ct_len,
                                  uint8_t       *ss_out, size_t ss_len)
{
    if (!param_set || !sk || !ct || !ss_out) return CRYSTALS_FFI_EARG;
    try {
        auto sz = mceliece_sz(param_set);
        if (!sz.sk || sk_len < sz.sk || ct_len < sz.ct || ss_len < 32)
            return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> sk_vec(sk, sk + sz.sk), ct_vec(ct, ct + sz.ct), ss;
        mceliece_kem::decaps(std::string(param_set), sk_vec, ct_vec, ss);
        std::memcpy(ss_out, ss.data(), 32);
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}
```

- [ ] **Step 5: Build and run C tests**

```bash
cmake --build shim/build -j$(nproc) && shim/build/test_shim
```
Expected: all tests PASS. Note: `test_mceliece_roundtrip` may take 1–3 seconds.

- [ ] **Step 6: Add MethodHandles to `CrystalsLib.java`**

Add after the EC sig block (line 103, before `private CrystalsLib() {}`):

```java
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
```

- [ ] **Step 7: Write `java/src/main/java/pqc/McElieceKEM.java`**

```java
package pqc;

import java.lang.foreign.*;

/**
 * McEliece KEM (code-based, long-term storage security).
 * Only mceliece348864f is practical for interactive use; others are very slow to keygen.
 */
public final class McElieceKEM {

    public enum Algorithm {
        MCELIECE_348864F, MCELIECE_460896F, MCELIECE_6688128F,
        MCELIECE_6960119F, MCELIECE_8192128F;

        String cName() {
            return switch (this) {
                case MCELIECE_348864F  -> "mceliece348864f";
                case MCELIECE_460896F  -> "mceliece460896f";
                case MCELIECE_6688128F -> "mceliece6688128f";
                case MCELIECE_6960119F -> "mceliece6960119f";
                case MCELIECE_8192128F -> "mceliece8192128f";
            };
        }
    }

    public static final int SS_BYTES = CrystalsLib.MCELIECE_SS_BYTES;

    public record KeyPair(byte[] pk, byte[] sk) {}
    public record EncapsResult(byte[] ct, byte[] ss) {}

    public static KeyPair keygen(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long pkLen = pkBytes(alg);
            long skLen = skBytes(alg);
            MemorySegment pk = arena.allocate(pkLen);
            MemorySegment sk = arena.allocate(skLen);
            int rc = (int) CrystalsLib.MCELIECE_KEYGEN.invokeExact(
                algSeg, pk, pkLen, sk, skLen);
            CrystalsLib.checkResult(rc, "mceliece_keygen");
            return new KeyPair(pk.toArray(ValueLayout.JAVA_BYTE),
                               sk.toArray(ValueLayout.JAVA_BYTE));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("mceliece_keygen failed", t);
        }
    }

    public static EncapsResult encaps(Algorithm alg, byte[] pk) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long pkLen = pkBytes(alg);
            long ctLen = ctBytes(alg);
            MemorySegment pkSeg = arena.allocate(pkLen);
            MemorySegment.copy(MemorySegment.ofArray(pk), 0, pkSeg, 0, pkLen);
            MemorySegment ctSeg = arena.allocate(ctLen);
            MemorySegment ssSeg = arena.allocate(SS_BYTES);
            int rc = (int) CrystalsLib.MCELIECE_ENCAPS.invokeExact(
                algSeg, pkSeg, pkLen, ctSeg, ctLen, ssSeg, (long) SS_BYTES);
            CrystalsLib.checkResult(rc, "mceliece_encaps");
            return new EncapsResult(ctSeg.toArray(ValueLayout.JAVA_BYTE),
                                    ssSeg.toArray(ValueLayout.JAVA_BYTE));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("mceliece_encaps failed", t);
        }
    }

    public static byte[] decaps(Algorithm alg, byte[] sk, byte[] ct) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long skLen = skBytes(alg);
            long ctLen = ctBytes(alg);
            MemorySegment skSeg = arena.allocate(skLen);
            MemorySegment.copy(MemorySegment.ofArray(sk), 0, skSeg, 0, skLen);
            MemorySegment ctSeg = arena.allocate(ctLen);
            MemorySegment.copy(MemorySegment.ofArray(ct), 0, ctSeg, 0, ctLen);
            MemorySegment ssSeg = arena.allocate(SS_BYTES);
            int rc = (int) CrystalsLib.MCELIECE_DECAPS.invokeExact(
                algSeg, skSeg, skLen, ctSeg, ctLen, ssSeg, (long) SS_BYTES);
            CrystalsLib.checkResult(rc, "mceliece_decaps");
            return ssSeg.toArray(ValueLayout.JAVA_BYTE);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("mceliece_decaps failed", t);
        }
    }

    public static int pkBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.MCELIECE_PK_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("mceliece_pk_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("mceliece_pk_bytes", t); }
    }

    public static int skBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.MCELIECE_SK_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("mceliece_sk_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("mceliece_sk_bytes", t); }
    }

    public static int ctBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.MCELIECE_CT_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("mceliece_ct_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("mceliece_ct_bytes", t); }
    }

    private McElieceKEM() {}
}
```

- [ ] **Step 8: Write `java/src/test/java/pqc/McElieceKEMTest.java`**

```java
package pqc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.*;
import java.util.concurrent.TimeUnit;

class McElieceKEMTest {

    /* Only the smallest variant is practical in a test suite — keygen is slow */
    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void roundtrip_348864f() {
        var alg = McElieceKEM.Algorithm.MCELIECE_348864F;
        var kp  = McElieceKEM.keygen(alg);
        var enc = McElieceKEM.encaps(alg, kp.pk());
        var ss  = McElieceKEM.decaps(alg, kp.sk(), enc.ct());
        assertArrayEquals(enc.ss(), ss, "shared secrets must match");
        assertEquals(McElieceKEM.SS_BYTES, ss.length);
    }
}
```

- [ ] **Step 9: Run Maven tests**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc-java/java
mvn test -Dtest=McElieceKEMTest
```
Expected: 1 test PASS (may take up to ~5 seconds for keygen).

- [ ] **Step 10: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc-java
git add shim/include/crystals_ffi.h shim/src/crystals_ffi.cpp shim/test/test_shim.c \
        java/src/main/java/pqc/CrystalsLib.java \
        java/src/main/java/pqc/McElieceKEM.java \
        java/src/test/java/pqc/McElieceKEMTest.java
git commit -m "feat(shim+java): McEliece KEM — keygen/encaps/decaps + 1 roundtrip test OK"
```

---

## Task 2: SLH-DSA Signatures

**Files:**
- Modify: `shim/include/crystals_ffi.h`
- Modify: `shim/src/crystals_ffi.cpp`
- Modify: `shim/test/test_shim.c`
- Modify: `java/src/main/java/pqc/CrystalsLib.java`
- Create: `java/src/main/java/pqc/SlhDsaSig.java`
- Create: `java/src/test/java/pqc/SlhDsaTest.java`

- [ ] **Step 1: Write the failing C test**

Add to `shim/test/test_shim.c`:

```c
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
```

Add `RUN(slhdsa_roundtrips);` to `main()`.

- [ ] **Step 2: Add declarations to `shim/include/crystals_ffi.h`**

```c
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
```

- [ ] **Step 3: Implement in `shim/src/crystals_ffi.cpp`**

Add static size helpers (outside `extern "C"`):

```cpp
struct SlhDsaSizes { size_t pk, sk; };
static SlhDsaSizes slhdsa_sz(const char *n) {
    if (!n) return {0,0};
    std::string s(n);
    if (s=="SLH-DSA-SHA2-128f"  || s=="SLH-DSA-SHAKE-128f")  return {32, 64};
    if (s=="SLH-DSA-SHA2-192f"  || s=="SLH-DSA-SHAKE-192f")  return {48, 96};
    if (s=="SLH-DSA-SHA2-256f"  || s=="SLH-DSA-SHAKE-256f")  return {64,128};
    return {0,0};
}
```

Inside `extern "C"`:

```cpp
size_t crystals_ffi_slhdsa_pk_bytes(const char *n) { return slhdsa_sz(n).pk; }
size_t crystals_ffi_slhdsa_sk_bytes(const char *n) { return slhdsa_sz(n).sk; }
size_t crystals_ffi_slhdsa_sig_bytes(const char *n) {
    if (!n) return 0;
    try { return slhdsa_sig::sig_bytes(std::string(n)); } catch (...) { return 0; }
}

int crystals_ffi_slhdsa_keygen(const char *alg_name,
                                uint8_t *pk_out, size_t pk_len,
                                uint8_t *sk_out, size_t sk_len)
{
    if (!alg_name || !pk_out || !sk_out) return CRYSTALS_FFI_EARG;
    try {
        auto sz = slhdsa_sz(alg_name);
        if (!sz.pk || pk_len < sz.pk || sk_len < sz.sk) return CRYSTALS_FFI_EARG;
        auto keys = mcs::keygen_slhdsa(std::string(alg_name));
        std::memcpy(pk_out, keys.pk.data(), keys.pk.size());
        std::memcpy(sk_out, keys.sk.data(), keys.sk.size());
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_slhdsa_sign(const char *alg_name,
                              const uint8_t *sk,      size_t sk_len,
                              const uint8_t *msg,     size_t msg_len,
                              uint8_t       *sig_out, size_t sig_len)
{
    if (!alg_name || !sk || !msg || !sig_out) return CRYSTALS_FFI_EARG;
    try {
        auto sz = slhdsa_sz(alg_name);
        size_t expected_sig = slhdsa_sig::sig_bytes(std::string(alg_name));
        if (!sz.sk || sk_len < sz.sk || sig_len < expected_sig) return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> sk_vec(sk, sk + sz.sk);
        std::vector<uint8_t> msg_vec(msg, msg + msg_len);
        std::vector<uint8_t> sig;
        slhdsa_sig::sign(std::string(alg_name), sk_vec, msg_vec, sig);
        std::memcpy(sig_out, sig.data(), sig.size());
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_slhdsa_verify(const char *alg_name,
                                const uint8_t *pk,  size_t pk_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len)
{
    if (!alg_name || !pk || !msg || !sig) return CRYSTALS_FFI_EARG;
    try {
        auto sz = slhdsa_sz(alg_name);
        size_t expected_sig = slhdsa_sig::sig_bytes(std::string(alg_name));
        if (!sz.pk || pk_len < sz.pk || sig_len < expected_sig) return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> pk_vec(pk, pk + sz.pk);
        std::vector<uint8_t> msg_vec(msg, msg + msg_len);
        std::vector<uint8_t> sig_vec(sig, sig + expected_sig);
        bool ok = slhdsa_sig::verify(std::string(alg_name), pk_vec, msg_vec, sig_vec);
        return ok ? CRYSTALS_FFI_OK : CRYSTALS_FFI_ECRYPTO;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}
```

- [ ] **Step 4: Build and run C tests**

```bash
cmake --build shim/build -j$(nproc) && shim/build/test_shim
```
Expected: all tests PASS (SLH-DSA "f" variants sign in under 1 second each).

- [ ] **Step 5: Add MethodHandles to `CrystalsLib.java`**

```java
// ── SLH-DSA signatures ────────────────────────────────────────────────────────
static final MethodHandle SLHDSA_PK_BYTES = mh("crystals_ffi_slhdsa_pk_bytes",
    FunctionDescriptor.of(LONG, ADDR));
static final MethodHandle SLHDSA_SK_BYTES = mh("crystals_ffi_slhdsa_sk_bytes",
    FunctionDescriptor.of(LONG, ADDR));
static final MethodHandle SLHDSA_SIG_BYTES = mh("crystals_ffi_slhdsa_sig_bytes",
    FunctionDescriptor.of(LONG, ADDR));
static final MethodHandle SLHDSA_KEYGEN = mh("crystals_ffi_slhdsa_keygen",
    FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG));
static final MethodHandle SLHDSA_SIGN = mh("crystals_ffi_slhdsa_sign",
    FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG, ADDR, LONG));
static final MethodHandle SLHDSA_VERIFY = mh("crystals_ffi_slhdsa_verify",
    FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG, ADDR, LONG));
```

- [ ] **Step 6: Write `java/src/main/java/pqc/SlhDsaSig.java`**

```java
package pqc;

import java.lang.foreign.*;

/**
 * SLH-DSA (SPHINCS+) signatures: SHA2-128f, SHA2-192f, SHAKE-192f, SHA2-256f, SHAKE-256f.
 * All are "fast" (f) parameter sets; signing takes milliseconds to ~100ms.
 */
public final class SlhDsaSig {

    public enum Algorithm {
        SHA2_128F, SHA2_192F, SHAKE_192F, SHA2_256F, SHAKE_256F;

        String cName() {
            return switch (this) {
                case SHA2_128F  -> "SLH-DSA-SHA2-128f";
                case SHA2_192F  -> "SLH-DSA-SHA2-192f";
                case SHAKE_192F -> "SLH-DSA-SHAKE-192f";
                case SHA2_256F  -> "SLH-DSA-SHA2-256f";
                case SHAKE_256F -> "SLH-DSA-SHAKE-256f";
            };
        }
    }

    public record KeyPair(byte[] pk, byte[] sk) {}

    public static KeyPair keygen(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long pkLen = pkBytes(alg);
            long skLen = skBytes(alg);
            MemorySegment pk = arena.allocate(pkLen);
            MemorySegment sk = arena.allocate(skLen);
            int rc = (int) CrystalsLib.SLHDSA_KEYGEN.invokeExact(
                algSeg, pk, pkLen, sk, skLen);
            CrystalsLib.checkResult(rc, "slhdsa_keygen");
            return new KeyPair(pk.toArray(ValueLayout.JAVA_BYTE),
                               sk.toArray(ValueLayout.JAVA_BYTE));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("slhdsa_keygen failed", t);
        }
    }

    public static byte[] sign(Algorithm alg, byte[] sk, byte[] msg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long skLen  = skBytes(alg);
            long sigLen = sigBytes(alg);
            MemorySegment skSeg  = arena.allocate(skLen);
            MemorySegment.copy(MemorySegment.ofArray(sk), 0, skSeg, 0, skLen);
            MemorySegment msgSeg = arena.allocate(msg.length);
            MemorySegment.copy(MemorySegment.ofArray(msg), 0, msgSeg, 0, msg.length);
            MemorySegment sigSeg = arena.allocate(sigLen);
            int rc = (int) CrystalsLib.SLHDSA_SIGN.invokeExact(
                algSeg, skSeg, skLen, msgSeg, (long) msg.length, sigSeg, sigLen);
            CrystalsLib.checkResult(rc, "slhdsa_sign");
            return sigSeg.toArray(ValueLayout.JAVA_BYTE);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("slhdsa_sign failed", t);
        }
    }

    public static boolean verify(Algorithm alg, byte[] pk, byte[] msg, byte[] sig) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long pkLen  = pkBytes(alg);
            long sigLen = sigBytes(alg);
            MemorySegment pkSeg  = arena.allocate(pkLen);
            MemorySegment.copy(MemorySegment.ofArray(pk), 0, pkSeg, 0, pkLen);
            MemorySegment msgSeg = arena.allocate(msg.length);
            MemorySegment.copy(MemorySegment.ofArray(msg), 0, msgSeg, 0, msg.length);
            MemorySegment sigSeg = arena.allocate(sigLen);
            MemorySegment.copy(MemorySegment.ofArray(sig), 0, sigSeg, 0,
                Math.min(sig.length, sigLen));
            int rc = (int) CrystalsLib.SLHDSA_VERIFY.invokeExact(
                algSeg, pkSeg, pkLen, msgSeg, (long) msg.length, sigSeg, sigLen);
            if (rc == CrystalsLib.ECRYPTO) return false;
            CrystalsLib.checkResult(rc, "slhdsa_verify");
            return true;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("slhdsa_verify failed", t);
        }
    }

    public static int pkBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.SLHDSA_PK_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("slhdsa_pk_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("slhdsa_pk_bytes", t); }
    }

    public static int skBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.SLHDSA_SK_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("slhdsa_sk_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("slhdsa_sk_bytes", t); }
    }

    public static int sigBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.SLHDSA_SIG_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("slhdsa_sig_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("slhdsa_sig_bytes", t); }
    }

    private SlhDsaSig() {}
}
```

- [ ] **Step 7: Write `java/src/test/java/pqc/SlhDsaTest.java`**

```java
package pqc;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class SlhDsaTest {

    private static final byte[] MSG     = "hello post-quantum world".getBytes();
    private static final byte[] BAD_MSG = "hello post-quantum WORLD".getBytes();

    @ParameterizedTest
    @EnumSource(SlhDsaSig.Algorithm.class)
    void roundtrip(SlhDsaSig.Algorithm alg) {
        var kp  = SlhDsaSig.keygen(alg);
        var sig = SlhDsaSig.sign(alg, kp.sk(), MSG);
        assertTrue(SlhDsaSig.verify(alg, kp.pk(), MSG, sig),
            "valid sig must verify for " + alg);
        assertFalse(SlhDsaSig.verify(alg, kp.pk(), BAD_MSG, sig),
            "tampered msg must not verify for " + alg);
    }
}
```

- [ ] **Step 8: Run Maven tests**

```bash
mvn test -Dtest=SlhDsaTest
```
Expected: 5 tests PASS.

- [ ] **Step 9: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc-java
git add shim/include/crystals_ffi.h shim/src/crystals_ffi.cpp shim/test/test_shim.c \
        java/src/main/java/pqc/CrystalsLib.java \
        java/src/main/java/pqc/SlhDsaSig.java \
        java/src/test/java/pqc/SlhDsaTest.java
git commit -m "feat(shim+java): SLH-DSA — keygen/sign/verify all 5 variants + tamper detection OK"
```

---

## Task 3: OQS KEM (ML-KEM + FrodoKEM)

**Files:**
- Modify: `shim/include/crystals_ffi.h`
- Modify: `shim/src/crystals_ffi.cpp`
- Modify: `shim/test/test_shim.c`
- Modify: `java/src/main/java/pqc/CrystalsLib.java`
- Create: `java/src/main/java/pqc/OqsKEM.java`
- Create: `java/src/test/java/pqc/OqsKEMTest.java`

- [ ] **Step 1: Write the failing C test**

```c
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
```

Add `RUN(oqs_kem_roundtrips);` to `main()`.

- [ ] **Step 2: Add declarations to `shim/include/crystals_ffi.h`**

```c
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
```

- [ ] **Step 3: Implement in `shim/src/crystals_ffi.cpp`**

Add static size helpers (outside `extern "C"`):

```cpp
struct OqsKemSizes { size_t pk, sk, ct, ss; };
static OqsKemSizes oqs_kem_sz(const char *n) {
    if (!n) return {0,0,0,0};
    std::string s(n);
    if (s=="ML-KEM-512")          return {  800,  1632,   768, 32};
    if (s=="ML-KEM-768")          return { 1184,  2400,  1088, 32};
    if (s=="ML-KEM-1024")         return { 1568,  3168,  1568, 32};
    if (s=="FrodoKEM-640-AES")    return { 9616, 19888,  9752, 16};
    if (s=="FrodoKEM-976-AES")    return {15632, 31296, 15792, 24};
    if (s=="FrodoKEM-1344-AES")   return {21520, 43088, 21696, 32};
    return {0,0,0,0};
}
```

Inside `extern "C"`:

```cpp
size_t crystals_ffi_oqs_kem_pk_bytes(const char *n) { return oqs_kem_sz(n).pk; }
size_t crystals_ffi_oqs_kem_sk_bytes(const char *n) { return oqs_kem_sz(n).sk; }
size_t crystals_ffi_oqs_kem_ct_bytes(const char *n) { return oqs_kem_sz(n).ct; }
size_t crystals_ffi_oqs_kem_ss_bytes(const char *n) { return oqs_kem_sz(n).ss; }

int crystals_ffi_oqs_kem_keygen(const char *alg_name,
                                  uint8_t *pk_out, size_t pk_len,
                                  uint8_t *sk_out, size_t sk_len)
{
    if (!alg_name || !pk_out || !sk_out) return CRYSTALS_FFI_EARG;
    try {
        auto sz = oqs_kem_sz(alg_name);
        if (!sz.pk || pk_len < sz.pk || sk_len < sz.sk) return CRYSTALS_FFI_EARG;
        auto keys = oqs_kem::keygen(std::string(alg_name));
        std::memcpy(pk_out, keys.pk.data(), sz.pk);
        std::memcpy(sk_out, keys.sk.data(), sz.sk);
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_oqs_kem_encaps(const char *alg_name,
                                  const uint8_t *pk,     size_t pk_len,
                                  uint8_t       *ct_out, size_t ct_len,
                                  uint8_t       *ss_out, size_t ss_len)
{
    if (!alg_name || !pk || !ct_out || !ss_out) return CRYSTALS_FFI_EARG;
    try {
        auto sz = oqs_kem_sz(alg_name);
        if (!sz.pk || pk_len < sz.pk || ct_len < sz.ct || ss_len < sz.ss)
            return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> pk_vec(pk, pk + sz.pk), ct, ss;
        oqs_kem::encaps(std::string(alg_name), pk_vec, ct, ss);
        std::memcpy(ct_out, ct.data(), sz.ct);
        std::memcpy(ss_out, ss.data(), sz.ss);
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_oqs_kem_decaps(const char *alg_name,
                                  const uint8_t *sk,     size_t sk_len,
                                  const uint8_t *ct,     size_t ct_len,
                                  uint8_t       *ss_out, size_t ss_len)
{
    if (!alg_name || !sk || !ct || !ss_out) return CRYSTALS_FFI_EARG;
    try {
        auto sz = oqs_kem_sz(alg_name);
        if (!sz.sk || sk_len < sz.sk || ct_len < sz.ct || ss_len < sz.ss)
            return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> sk_vec(sk, sk + sz.sk), ct_vec(ct, ct + sz.ct), ss;
        oqs_kem::decaps(std::string(alg_name), sk_vec, ct_vec, ss);
        std::memcpy(ss_out, ss.data(), sz.ss);
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}
```

- [ ] **Step 4: Build and run C tests**

```bash
cmake --build shim/build -j$(nproc) && shim/build/test_shim
```
Expected: all tests PASS (FrodoKEM roundtrips may take a few seconds total).

- [ ] **Step 5: Add MethodHandles to `CrystalsLib.java`**

```java
// ── OQS KEM (ML-KEM + FrodoKEM) ──────────────────────────────────────────────
static final MethodHandle OQS_KEM_PK_BYTES = mh("crystals_ffi_oqs_kem_pk_bytes",
    FunctionDescriptor.of(LONG, ADDR));
static final MethodHandle OQS_KEM_SK_BYTES = mh("crystals_ffi_oqs_kem_sk_bytes",
    FunctionDescriptor.of(LONG, ADDR));
static final MethodHandle OQS_KEM_CT_BYTES = mh("crystals_ffi_oqs_kem_ct_bytes",
    FunctionDescriptor.of(LONG, ADDR));
static final MethodHandle OQS_KEM_SS_BYTES = mh("crystals_ffi_oqs_kem_ss_bytes",
    FunctionDescriptor.of(LONG, ADDR));
static final MethodHandle OQS_KEM_KEYGEN = mh("crystals_ffi_oqs_kem_keygen",
    FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG));
static final MethodHandle OQS_KEM_ENCAPS = mh("crystals_ffi_oqs_kem_encaps",
    FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG, ADDR, LONG));
static final MethodHandle OQS_KEM_DECAPS = mh("crystals_ffi_oqs_kem_decaps",
    FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG, ADDR, LONG));
```

- [ ] **Step 6: Write `java/src/main/java/pqc/OqsKEM.java`**

```java
package pqc;

import java.lang.foreign.*;

/**
 * OQS KEMs: ML-KEM (NIST FIPS 203, levels 512/768/1024)
 *           FrodoKEM-AES (640/976/1344 — lattice-based, conservative).
 */
public final class OqsKEM {

    public enum Algorithm {
        ML_KEM_512, ML_KEM_768, ML_KEM_1024,
        FRODOKEM_640_AES, FRODOKEM_976_AES, FRODOKEM_1344_AES;

        String cName() {
            return switch (this) {
                case ML_KEM_512        -> "ML-KEM-512";
                case ML_KEM_768        -> "ML-KEM-768";
                case ML_KEM_1024       -> "ML-KEM-1024";
                case FRODOKEM_640_AES  -> "FrodoKEM-640-AES";
                case FRODOKEM_976_AES  -> "FrodoKEM-976-AES";
                case FRODOKEM_1344_AES -> "FrodoKEM-1344-AES";
            };
        }
    }

    public record KeyPair(byte[] pk, byte[] sk) {}
    public record EncapsResult(byte[] ct, byte[] ss) {}

    public static KeyPair keygen(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long pkLen = pkBytes(alg);
            long skLen = skBytes(alg);
            MemorySegment pk = arena.allocate(pkLen);
            MemorySegment sk = arena.allocate(skLen);
            int rc = (int) CrystalsLib.OQS_KEM_KEYGEN.invokeExact(
                algSeg, pk, pkLen, sk, skLen);
            CrystalsLib.checkResult(rc, "oqs_kem_keygen");
            return new KeyPair(pk.toArray(ValueLayout.JAVA_BYTE),
                               sk.toArray(ValueLayout.JAVA_BYTE));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("oqs_kem_keygen failed", t);
        }
    }

    public static EncapsResult encaps(Algorithm alg, byte[] pk) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long pkLen = pkBytes(alg);
            long ctLen = ctBytes(alg);
            long ssLen = ssBytes(alg);
            MemorySegment pkSeg = arena.allocate(pkLen);
            MemorySegment.copy(MemorySegment.ofArray(pk), 0, pkSeg, 0, pkLen);
            MemorySegment ctSeg = arena.allocate(ctLen);
            MemorySegment ssSeg = arena.allocate(ssLen);
            int rc = (int) CrystalsLib.OQS_KEM_ENCAPS.invokeExact(
                algSeg, pkSeg, pkLen, ctSeg, ctLen, ssSeg, ssLen);
            CrystalsLib.checkResult(rc, "oqs_kem_encaps");
            return new EncapsResult(ctSeg.toArray(ValueLayout.JAVA_BYTE),
                                    ssSeg.toArray(ValueLayout.JAVA_BYTE));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("oqs_kem_encaps failed", t);
        }
    }

    public static byte[] decaps(Algorithm alg, byte[] sk, byte[] ct) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long skLen = skBytes(alg);
            long ctLen = ctBytes(alg);
            long ssLen = ssBytes(alg);
            MemorySegment skSeg = arena.allocate(skLen);
            MemorySegment.copy(MemorySegment.ofArray(sk), 0, skSeg, 0, skLen);
            MemorySegment ctSeg = arena.allocate(ctLen);
            MemorySegment.copy(MemorySegment.ofArray(ct), 0, ctSeg, 0, ctLen);
            MemorySegment ssSeg = arena.allocate(ssLen);
            int rc = (int) CrystalsLib.OQS_KEM_DECAPS.invokeExact(
                algSeg, skSeg, skLen, ctSeg, ctLen, ssSeg, ssLen);
            CrystalsLib.checkResult(rc, "oqs_kem_decaps");
            return ssSeg.toArray(ValueLayout.JAVA_BYTE);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("oqs_kem_decaps failed", t);
        }
    }

    public static int pkBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.OQS_KEM_PK_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("oqs_kem_pk_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("oqs_kem_pk_bytes", t); }
    }

    public static int skBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.OQS_KEM_SK_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("oqs_kem_sk_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("oqs_kem_sk_bytes", t); }
    }

    public static int ctBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.OQS_KEM_CT_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("oqs_kem_ct_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("oqs_kem_ct_bytes", t); }
    }

    public static int ssBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.OQS_KEM_SS_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("oqs_kem_ss_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("oqs_kem_ss_bytes", t); }
    }

    private OqsKEM() {}
}
```

- [ ] **Step 7: Write `java/src/test/java/pqc/OqsKEMTest.java`**

```java
package pqc;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class OqsKEMTest {

    @ParameterizedTest
    @EnumSource(OqsKEM.Algorithm.class)
    void roundtrip(OqsKEM.Algorithm alg) {
        var kp  = OqsKEM.keygen(alg);
        var enc = OqsKEM.encaps(alg, kp.pk());
        var ss  = OqsKEM.decaps(alg, kp.sk(), enc.ct());
        assertArrayEquals(enc.ss(), ss, "shared secrets must match for " + alg);
        assertEquals(OqsKEM.ssBytes(alg), ss.length);
    }
}
```

- [ ] **Step 8: Run Maven tests**

```bash
mvn test -Dtest=OqsKEMTest
```
Expected: 6 tests PASS (FrodoKEM variants may take a few seconds each).

- [ ] **Step 9: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc-java
git add shim/include/crystals_ffi.h shim/src/crystals_ffi.cpp shim/test/test_shim.c \
        java/src/main/java/pqc/CrystalsLib.java \
        java/src/main/java/pqc/OqsKEM.java \
        java/src/test/java/pqc/OqsKEMTest.java
git commit -m "feat(shim+java): OQS KEM — ML-KEM 512/768/1024 + FrodoKEM 640/976/1344 roundtrips OK"
```

---

## Task 4: OQS Sig (ML-DSA + Falcon)

**Files:**
- Modify: `shim/include/crystals_ffi.h`
- Modify: `shim/src/crystals_ffi.cpp`
- Modify: `shim/test/test_shim.c`
- Modify: `java/src/main/java/pqc/CrystalsLib.java`
- Create: `java/src/main/java/pqc/OqsSig.java`
- Create: `java/src/test/java/pqc/OqsSigTest.java`

**Key design:** `oqs_sig_sign` has an extra `size_t *actual_sig_len` out-parameter because Falcon produces variable-length signatures (actual ≤ max). ML-DSA produces fixed-length signatures (actual == max). The Java side uses `Arrays.copyOf` to trim the return buffer to the actual length.

- [ ] **Step 1: Write the failing C test**

```c
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
```

Add `RUN(oqs_sig_roundtrips);` to `main()`.

- [ ] **Step 2: Add declarations to `shim/include/crystals_ffi.h`**

```c
/* ── OQS signatures (alg_name: "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" |
                                "Falcon-512" | "Falcon-1024") ── */
size_t crystals_ffi_oqs_sig_pk_bytes(const char *alg_name);
size_t crystals_ffi_oqs_sig_sk_bytes(const char *alg_name);
size_t crystals_ffi_oqs_sig_bytes(const char *alg_name);    /* max sig size */

int crystals_ffi_oqs_sig_keygen(const char *alg_name,
                                  uint8_t *pk_out, size_t pk_len,
                                  uint8_t *sk_out, size_t sk_len);

/* actual_sig_len is set to the real signature length (≤ sig_max).
   For ML-DSA this equals sig_max; for Falcon it may be smaller. */
int crystals_ffi_oqs_sig_sign(const char *alg_name,
                               const uint8_t *sk,       size_t sk_len,
                               const uint8_t *msg,      size_t msg_len,
                               uint8_t       *sig_out,  size_t sig_max,
                               size_t        *actual_sig_len);

/* sig_len must be the ACTUAL signature length returned by sign. */
int crystals_ffi_oqs_sig_verify(const char *alg_name,
                                 const uint8_t *pk,  size_t pk_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len);
```

- [ ] **Step 3: Implement in `shim/src/crystals_ffi.cpp`**

Add static size helpers (outside `extern "C"`):

```cpp
struct OqsSigSizes { size_t pk, sk, sig_max; };
static OqsSigSizes oqs_sig_sz(const char *n) {
    if (!n) return {0,0,0};
    std::string s(n);
    if (s=="ML-DSA-44")   return {1312, 2560, 2420};
    if (s=="ML-DSA-65")   return {1952, 4032, 3309};
    if (s=="ML-DSA-87")   return {2592, 4896, 4627};
    if (s=="Falcon-512")  return { 897, 1281,  752};
    if (s=="Falcon-1024") return {1793, 2305, 1462};
    return {0,0,0};
}
```

Inside `extern "C"`:

```cpp
size_t crystals_ffi_oqs_sig_pk_bytes(const char *n) { return oqs_sig_sz(n).pk; }
size_t crystals_ffi_oqs_sig_sk_bytes(const char *n) { return oqs_sig_sz(n).sk; }
size_t crystals_ffi_oqs_sig_bytes(const char *n) {
    if (!n) return 0;
    try { return oqs_sig::sig_bytes(std::string(n)); } catch (...) { return 0; }
}

int crystals_ffi_oqs_sig_keygen(const char *alg_name,
                                  uint8_t *pk_out, size_t pk_len,
                                  uint8_t *sk_out, size_t sk_len)
{
    if (!alg_name || !pk_out || !sk_out) return CRYSTALS_FFI_EARG;
    try {
        auto sz = oqs_sig_sz(alg_name);
        if (!sz.pk || pk_len < sz.pk || sk_len < sz.sk) return CRYSTALS_FFI_EARG;
        auto keys = oqs_sig::keygen(std::string(alg_name));
        std::memcpy(pk_out, keys.pk.data(), sz.pk);
        std::memcpy(sk_out, keys.sk.data(), sz.sk);
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_oqs_sig_sign(const char *alg_name,
                               const uint8_t *sk,       size_t sk_len,
                               const uint8_t *msg,      size_t msg_len,
                               uint8_t       *sig_out,  size_t sig_max,
                               size_t        *actual_sig_len)
{
    if (!alg_name || !sk || !msg || !sig_out || !actual_sig_len) return CRYSTALS_FFI_EARG;
    try {
        auto sz = oqs_sig_sz(alg_name);
        if (!sz.sk || sk_len < sz.sk || sig_max < sz.sig_max) return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> sk_vec(sk, sk + sz.sk);
        std::vector<uint8_t> msg_vec(msg, msg + msg_len);
        std::vector<uint8_t> sig;
        oqs_sig::sign(std::string(alg_name), sk_vec, msg_vec, sig);
        std::memcpy(sig_out, sig.data(), sig.size());
        *actual_sig_len = sig.size();
        return CRYSTALS_FFI_OK;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}

int crystals_ffi_oqs_sig_verify(const char *alg_name,
                                 const uint8_t *pk,  size_t pk_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len)
{
    if (!alg_name || !pk || !msg || !sig) return CRYSTALS_FFI_EARG;
    try {
        auto sz = oqs_sig_sz(alg_name);
        if (!sz.pk || pk_len < sz.pk || sig_len == 0) return CRYSTALS_FFI_EARG;
        std::vector<uint8_t> pk_vec(pk, pk + sz.pk);
        std::vector<uint8_t> msg_vec(msg, msg + msg_len);
        std::vector<uint8_t> sig_vec(sig, sig + sig_len);
        bool ok = oqs_sig::verify(std::string(alg_name), pk_vec, msg_vec, sig_vec);
        return ok ? CRYSTALS_FFI_OK : CRYSTALS_FFI_ECRYPTO;
    } catch (const std::invalid_argument&) {
        return CRYSTALS_FFI_EARG;
    } catch (...) {
        return CRYSTALS_FFI_EUNKNOWN;
    }
}
```

- [ ] **Step 4: Build and run C tests**

```bash
cmake --build shim/build -j$(nproc) && shim/build/test_shim
```
Expected: all tests PASS.

- [ ] **Step 5: Add MethodHandles to `CrystalsLib.java`**

```java
// ── OQS signatures (ML-DSA + Falcon) ─────────────────────────────────────────
static final MethodHandle OQS_SIG_PK_BYTES = mh("crystals_ffi_oqs_sig_pk_bytes",
    FunctionDescriptor.of(LONG, ADDR));
static final MethodHandle OQS_SIG_SK_BYTES = mh("crystals_ffi_oqs_sig_sk_bytes",
    FunctionDescriptor.of(LONG, ADDR));
static final MethodHandle OQS_SIG_BYTES = mh("crystals_ffi_oqs_sig_bytes",
    FunctionDescriptor.of(LONG, ADDR));
static final MethodHandle OQS_SIG_KEYGEN = mh("crystals_ffi_oqs_sig_keygen",
    FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG));
// sign: alg, sk, sk_len, msg, msg_len, sig_out, sig_max, actual_sig_len*
static final MethodHandle OQS_SIG_SIGN = mh("crystals_ffi_oqs_sig_sign",
    FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG, ADDR, LONG, ADDR));
// verify: alg, pk, pk_len, msg, msg_len, sig, sig_len
static final MethodHandle OQS_SIG_VERIFY = mh("crystals_ffi_oqs_sig_verify",
    FunctionDescriptor.of(INT, ADDR, ADDR, LONG, ADDR, LONG, ADDR, LONG));
```

- [ ] **Step 6: Write `java/src/main/java/pqc/OqsSig.java`**

```java
package pqc;

import java.lang.foreign.*;
import java.util.Arrays;

/**
 * OQS signatures: ML-DSA (NIST FIPS 204, modes 44/65/87)
 *                 Falcon-512 and Falcon-1024 (NIST Round-4, fast/compact).
 *
 * IMPORTANT: Falcon produces variable-length signatures. sign() returns a byte[]
 * whose length is the ACTUAL signature length (≤ sigBytes(alg)). Always pass
 * the exact returned array to verify() — do NOT pad or trim it.
 */
public final class OqsSig {

    public enum Algorithm {
        ML_DSA_44, ML_DSA_65, ML_DSA_87, FALCON_512, FALCON_1024;

        String cName() {
            return switch (this) {
                case ML_DSA_44   -> "ML-DSA-44";
                case ML_DSA_65   -> "ML-DSA-65";
                case ML_DSA_87   -> "ML-DSA-87";
                case FALCON_512  -> "Falcon-512";
                case FALCON_1024 -> "Falcon-1024";
            };
        }
    }

    public record KeyPair(byte[] pk, byte[] sk) {}

    public static KeyPair keygen(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long pkLen = pkBytes(alg);
            long skLen = skBytes(alg);
            MemorySegment pk = arena.allocate(pkLen);
            MemorySegment sk = arena.allocate(skLen);
            int rc = (int) CrystalsLib.OQS_SIG_KEYGEN.invokeExact(
                algSeg, pk, pkLen, sk, skLen);
            CrystalsLib.checkResult(rc, "oqs_sig_keygen");
            return new KeyPair(pk.toArray(ValueLayout.JAVA_BYTE),
                               sk.toArray(ValueLayout.JAVA_BYTE));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("oqs_sig_keygen failed", t);
        }
    }

    /**
     * Sign msg. Returns a byte[] of the ACTUAL signature length.
     * For Falcon this is variable (≤ sigBytes(alg)); for ML-DSA it equals sigBytes(alg).
     */
    public static byte[] sign(Algorithm alg, byte[] sk, byte[] msg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long skLen  = skBytes(alg);
            long sigMax = sigBytes(alg);
            MemorySegment skSeg  = arena.allocate(skLen);
            MemorySegment.copy(MemorySegment.ofArray(sk), 0, skSeg, 0, skLen);
            MemorySegment msgSeg = arena.allocate(msg.length);
            MemorySegment.copy(MemorySegment.ofArray(msg), 0, msgSeg, 0, msg.length);
            MemorySegment sigSeg = arena.allocate(sigMax);
            MemorySegment actualLenSeg = arena.allocate(ValueLayout.JAVA_LONG);
            int rc = (int) CrystalsLib.OQS_SIG_SIGN.invokeExact(
                algSeg, skSeg, skLen, msgSeg, (long) msg.length,
                sigSeg, sigMax, actualLenSeg);
            CrystalsLib.checkResult(rc, "oqs_sig_sign");
            long actualLen = actualLenSeg.get(ValueLayout.JAVA_LONG, 0);
            return Arrays.copyOf(sigSeg.toArray(ValueLayout.JAVA_BYTE), (int) actualLen);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("oqs_sig_sign failed", t);
        }
    }

    /**
     * Verify sig against pk and msg. sig must be the exact byte[] returned by sign().
     */
    public static boolean verify(Algorithm alg, byte[] pk, byte[] msg, byte[] sig) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long pkLen = pkBytes(alg);
            MemorySegment pkSeg  = arena.allocate(pkLen);
            MemorySegment.copy(MemorySegment.ofArray(pk), 0, pkSeg, 0, pkLen);
            MemorySegment msgSeg = arena.allocate(msg.length);
            MemorySegment.copy(MemorySegment.ofArray(msg), 0, msgSeg, 0, msg.length);
            MemorySegment sigSeg = arena.allocate(sig.length);
            MemorySegment.copy(MemorySegment.ofArray(sig), 0, sigSeg, 0, sig.length);
            int rc = (int) CrystalsLib.OQS_SIG_VERIFY.invokeExact(
                algSeg, pkSeg, pkLen, msgSeg, (long) msg.length,
                sigSeg, (long) sig.length);
            if (rc == CrystalsLib.ECRYPTO) return false;
            CrystalsLib.checkResult(rc, "oqs_sig_verify");
            return true;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("oqs_sig_verify failed", t);
        }
    }

    public static int pkBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.OQS_SIG_PK_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("oqs_sig_pk_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("oqs_sig_pk_bytes", t); }
    }

    public static int skBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.OQS_SIG_SK_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("oqs_sig_sk_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("oqs_sig_sk_bytes", t); }
    }

    /** Returns the MAXIMUM signature size. Falcon actual sigs may be smaller. */
    public static int sigBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.OQS_SIG_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("oqs_sig_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("oqs_sig_bytes", t); }
    }

    private OqsSig() {}
}
```

- [ ] **Step 7: Write `java/src/test/java/pqc/OqsSigTest.java`**

```java
package pqc;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class OqsSigTest {

    private static final byte[] MSG     = "hello post-quantum world".getBytes();
    private static final byte[] BAD_MSG = "hello post-quantum WORLD".getBytes();

    @ParameterizedTest
    @EnumSource(OqsSig.Algorithm.class)
    void roundtrip(OqsSig.Algorithm alg) {
        var kp  = OqsSig.keygen(alg);
        var sig = OqsSig.sign(alg, kp.sk(), MSG);

        // Falcon sigs are variable-length; ML-DSA sigs are fixed
        assertTrue(sig.length > 0, "sig must be non-empty for " + alg);
        assertTrue(sig.length <= OqsSig.sigBytes(alg),
            "sig length must not exceed max for " + alg);

        assertTrue(OqsSig.verify(alg, kp.pk(), MSG, sig),
            "valid sig must verify for " + alg);
        assertFalse(OqsSig.verify(alg, kp.pk(), BAD_MSG, sig),
            "tampered msg must not verify for " + alg);
    }
}
```

- [ ] **Step 8: Run Maven tests**

```bash
mvn test -Dtest=OqsSigTest
```
Expected: 5 tests PASS.

- [ ] **Step 9: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc-java
git add shim/include/crystals_ffi.h shim/src/crystals_ffi.cpp shim/test/test_shim.c \
        java/src/main/java/pqc/CrystalsLib.java \
        java/src/main/java/pqc/OqsSig.java \
        java/src/test/java/pqc/OqsSigTest.java
git commit -m "feat(shim+java): OQS Sig — ML-DSA 44/65/87 + Falcon 512/1024 + variable-len handling OK"
```

---

## Task 5: Full Suite + Tag

- [ ] **Step 1: Run the full C shim test suite**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc-java
cmake --build shim/build -j$(nproc) && shim/build/test_shim
```
Expected: 11 tests PASS (kyber_sizes, dilithium_sizes, kyber_keygen, kyber_roundtrips, dilithium_roundtrips, ec_kem_roundtrips, ec_sig_roundtrips, mceliece_sizes, mceliece_roundtrip, slhdsa_roundtrips, oqs_kem_roundtrips, oqs_sig_roundtrips). Note: actual count depends on how many are wired in main().

- [ ] **Step 2: Run the full Maven test suite**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc-java/java
mvn test 2>&1 | grep -E "Tests run:|BUILD"
```
Expected: all tests pass across all 8 test classes.

- [ ] **Step 3: Tag v0.3-java**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc-java
git tag -a v0.3-java -m "Phase 3 complete: shim full coverage + Java bindings for all 4 profile groups"
```

- [ ] **Step 4: Commit the plan file**

```bash
git add docs/superpowers/plans/2026-03-27-shim-full-coverage.md
git commit -m "docs: add shim-full-coverage implementation plan"
```

---

## Self-Review

**Spec coverage:**
- ✅ McEliece KEM: keygen/encaps/decaps, all 5 param sets, size queries, SS=32 constant
- ✅ SLH-DSA: keygen/sign/verify, all 5 alg names, size queries
- ✅ OQS KEM: ML-KEM (3 levels) + FrodoKEM (3 variants), size queries including ss_bytes
- ✅ OQS Sig: ML-DSA (3 modes) + Falcon (2 levels), variable-length sign with actual_len out-param
- ✅ C shim size tables sourced from authoritative headers (libmceliece, liboqs)
- ✅ Java side handles Falcon variable-length via `Arrays.copyOf` + actual_len out-param
- ✅ verify() for OQS sig takes `sig.length` directly (actual, not max) — correct for both ML-DSA and Falcon

**Placeholder scan:** None found — all code blocks are complete.

**Type consistency:**
- All `cName()` return strings match the C shim's expected strings
- `OqsSig.sign()` returns `byte[]` of actual length; `OqsSig.verify()` passes `(long) sig.length` — consistent
- `McElieceKEM.SS_BYTES = 32` matches `CRYSTALS_FFI_MCELIECE_SS_BYTES = 32`
- All MethodHandle FunctionDescriptors match the C function signatures exactly
