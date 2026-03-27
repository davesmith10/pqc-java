# libcrystals-1.2: -fPIC Rebuild Requirement

**Raised by:** pqc-java shim project
**Date:** 2026-03-27
**Status:** Blocking shim shared-library build

---

## Summary

The pqc-java project needs to expose `libcrystals-1.2` functionality to Java via the Foreign
Function & Memory (FFM) API (Java 21 LTS). Java FFM can only load **shared libraries** (`.so`);
there is no mechanism to call into a static archive directly.

When building `libcrystals_ffi.so` (the C FFI shim) by linking against `/usr/local/lib/libcrystals-1.2.a`,
the linker fails with:

```
/usr/bin/ld: /usr/local/lib/libcrystals-1.2.a(libcrystals__000010__dilithium_sig.cpp.o):
    relocation R_X86_64_32 against `.rodata.str1.1' can not be used when making a shared object;
    recompile with -fPIC
/usr/bin/ld: /usr/local/lib/libcrystals-1.2.a(libpqcrystals_dilithium2_ref__000004__ntt.c.o):
    relocation R_X86_64_32S against `.rodata' can not be used when making a shared object;
    recompile with -fPIC
... (and likely more from scrypt, libmceliece, liboqs — linker exits after first few errors)
```

---

## Technical Background

A shared library (`.so`) is memory-mapped at an **arbitrary address** at load time (ASLR).
Every instruction in a `.so` must use position-independent addressing:

- **RIP-relative** addressing for code and read-only data (x86-64 native)
- **GOT** (Global Offset Table) for global variable access
- **PLT** (Procedure Linkage Table) for inter-library calls

`R_X86_64_32` and `R_X86_64_32S` are **absolute 32-bit** address relocations. These are
fine in executables and static archives (fixed load address), but the linker cannot generate
them in a shared library because there is no guarantee the library fits in the low 4 GB once
ASLR is in play.

The fix is to compile all constituent object files with `-fPIC` (or equivalently set
`CMAKE_POSITION_INDEPENDENT_CODE=ON` for CMake targets). On x86-64, -fPIC overhead is
near-zero — the ISA has RIP-relative addressing natively.

---

## Impact on Existing Consumers

**No regression expected.** A static archive compiled with `-fPIC` links identically into
executables and other static archives. `scotty`, `obi-wan`, and `padme` all link
`libcrystals-1.2.a` statically and will continue to work unchanged.

---

## Components That Need Rebuilding

The fat archive `libcrystals-1.2.a` is assembled by `pqc/libcrystals-1.2/install.sh` from
six source groups. All must produce PIC objects.

### 1. crystals cmake build  `pqc/libcrystals-1.2/`
**Build system:** CMake
**Current cmake invocation in `install.sh` (line 53–55):**
```bash
cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_PREFIX_PATH="${LOCAL_PREFIX}" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo
```
**Required change — add one flag:**
```bash
cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_PREFIX_PATH="${LOCAL_PREFIX}" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
```
This single flag covers:
- `libcrystals.a` (crystals C++ objects)
- `kyber_ref_build/libpqcrystals_kyber{512,768,1024}_ref.a`
- `kyber_ref_build/libpqcrystals_kyber_fips202_ref.a`
- `dilithium_ref_build/libpqcrystals_dilithium{2,3,5}_ref.a`
- `dilithium_ref_build/libpqcrystals_dilithium_fips202_ref.a`

All of these are built via `add_subdirectory` and inherit the `CMAKE_POSITION_INDEPENDENT_CODE`
property.

### 2. scrypt  `Crystals/scrypt/`
**Build system:** Autotools (cperciva libscrypt)
**Archives used:**
- `scrypt/.libs/libscrypt_sse2.a`
- `scrypt/.libs/libcperciva_cpusupport_detect.a`
- `scrypt/.libs/libcperciva_shani.a`

**Required change:** rebuild scrypt with `CFLAGS=-fPIC`. Typical invocation:
```bash
cd Crystals/scrypt
make clean
CFLAGS="-fPIC -O2" ./configure
make
```
Verify the `.libs/*.a` files are regenerated before running `install.sh`.

### 3. libmceliece  `/usr/local/lib/libmceliece.a`
**Build system:** Likely CMake
**Required change:** add `-DCMAKE_POSITION_INDEPENDENT_CODE=ON` to its cmake build, then
reinstall. Check whether the source is vendored in the Crystals tree or fetched separately.

### 4. liboqs  `/usr/local/lib64/liboqs.a`
**Build system:** CMake (Open Quantum Safe liboqs)
**Required change:** add `-DCMAKE_POSITION_INDEPENDENT_CODE=ON` to the liboqs cmake build,
then reinstall. liboqs's own cmake already supports this flag.

---

## Suggested install.sh Change (minimal diff)

```diff
-    cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" \
-        -DCMAKE_PREFIX_PATH="${LOCAL_PREFIX}" \
-        -DCMAKE_BUILD_TYPE=RelWithDebInfo
+    cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" \
+        -DCMAKE_PREFIX_PATH="${LOCAL_PREFIX}" \
+        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
+        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
```

---

## Regression Testing Checklist

After rebuilding all four component groups and running `sudo bash pqc/libcrystals-1.2/install.sh`:

- [ ] `scotty keygen --alias test --profile level2-25519` — generates valid YAML tray
- [ ] `scotty keygen --group mceliece+slhdsa --alias test --profile level2` — McEliece tray
- [ ] `obi-wan encrypt/decrypt` — all 16 combos (4 tray types × SHAKE/KMAC × AES/ChaCha20)
- [ ] `obi-wan sign/verify` (HYKE) — all crystals tray types
- [ ] `obi-wan pwencrypt/pwdecrypt` — all 3 Kyber levels
- [ ] `padme tray-encaps/tray-decaps` — at least one profile per group
- [ ] pqc-java shim: `cmake -S shim -B shim/build && cmake --build shim/build` links successfully as SHARED
- [ ] pqc-java shim: `./shim/build/test_shim` exits 0, all PASS
- [ ] pqc-java shim: `nm --dynamic shim/build/libcrystals_ffi.so | grep ' T '` shows only `crystals_ffi_*` symbols

---

## Resuming pqc-java After the Rebuild

The shim project is at commit `282e548` (Tasks 1 and 2 complete). Once the PIC-enabled
`libcrystals-1.2.a` is installed:

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc-java
rm -rf shim/build
cmake -S shim -B shim/build
cmake --build shim/build -j$(nproc)    # should now link cleanly as .so
./shim/build/test_shim                 # PASS: kyber_sizes, PASS: dilithium_sizes
```

Then continue from **Task 3** (Kyber KEM keygen) in the implementation plan.
