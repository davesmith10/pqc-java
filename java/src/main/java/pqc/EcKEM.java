package pqc;

import java.lang.foreign.*;

/**
 * EC KEM (Diffie-Hellman key encapsulation) over X25519, P-256, P-384, and P-521.
 * The ciphertext is the ephemeral public key; the shared secret is the DH output.
 */
public final class EcKEM {

    public enum Algorithm {
        X25519, P256, P384, P521;

        String cName() {
            return switch (this) {
                case X25519 -> "X25519";
                case P256   -> "P-256";
                case P384   -> "P-384";
                case P521   -> "P-521";
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
            int rc = (int) CrystalsLib.EC_KEM_KEYGEN.invokeExact(
                algSeg, pk, pkLen, sk, skLen);
            CrystalsLib.checkResult(rc, "ec_kem_keygen");
            return new KeyPair(pk.toArray(ValueLayout.JAVA_BYTE),
                               sk.toArray(ValueLayout.JAVA_BYTE));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("ec_kem_keygen failed", t);
        }
    }

    public static EncapsResult encaps(Algorithm alg, byte[] pk) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long pkLen = pkBytes(alg);
            long ctLen = ctBytes(alg);
            long ssLen = skBytes(alg); // ss size == sk size for all EC DH KEMs
            MemorySegment pkSeg = arena.allocate(pkLen);
            MemorySegment.copy(MemorySegment.ofArray(pk), 0, pkSeg, 0, pkLen);
            MemorySegment ctSeg = arena.allocate(ctLen);
            MemorySegment ssSeg = arena.allocate(ssLen);
            int rc = (int) CrystalsLib.EC_KEM_ENCAPS.invokeExact(
                algSeg, pkSeg, pkLen, ctSeg, ctLen, ssSeg, ssLen);
            CrystalsLib.checkResult(rc, "ec_kem_encaps");
            return new EncapsResult(ctSeg.toArray(ValueLayout.JAVA_BYTE),
                                    ssSeg.toArray(ValueLayout.JAVA_BYTE));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("ec_kem_encaps failed", t);
        }
    }

    public static byte[] decaps(Algorithm alg, byte[] sk, byte[] ct) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            long skLen = skBytes(alg);
            long ctLen = ctBytes(alg);
            long ssLen = skLen; // ss size == sk size
            MemorySegment skSeg = arena.allocate(skLen);
            MemorySegment.copy(MemorySegment.ofArray(sk), 0, skSeg, 0, skLen);
            MemorySegment ctSeg = arena.allocate(ctLen);
            MemorySegment.copy(MemorySegment.ofArray(ct), 0, ctSeg, 0, ctLen);
            MemorySegment ssSeg = arena.allocate(ssLen);
            int rc = (int) CrystalsLib.EC_KEM_DECAPS.invokeExact(
                algSeg, skSeg, skLen, ctSeg, ctLen, ssSeg, ssLen);
            CrystalsLib.checkResult(rc, "ec_kem_decaps");
            return ssSeg.toArray(ValueLayout.JAVA_BYTE);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("ec_kem_decaps failed", t);
        }
    }

    public static int pkBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.EC_KEM_PK_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("ec_kem_pk_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("ec_kem_pk_bytes", t); }
    }

    public static int skBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.EC_KEM_SK_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("ec_kem_sk_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("ec_kem_sk_bytes", t); }
    }

    public static int ctBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.EC_KEM_CT_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("ec_kem_ct_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("ec_kem_ct_bytes", t); }
    }

    private EcKEM() {}
}
