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
