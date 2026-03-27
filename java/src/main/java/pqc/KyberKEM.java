package pqc;

import java.lang.foreign.*;

/**
 * Kyber KEM (ML-KEM) at security levels 512, 768, and 1024.
 * All methods are stateless and thread-safe.
 */
public final class KyberKEM {

    public record KeyPair(byte[] pk, byte[] sk) {}
    public record EncapsResult(byte[] ct, byte[] ss) {}

    public static final int SS_BYTES = 32;

    public static KeyPair keygen(int level) {
        try (Arena arena = Arena.ofConfined()) {
            long pkLen = pkBytes(level);
            long skLen = skBytes(level);
            MemorySegment pk = arena.allocate(pkLen);
            MemorySegment sk = arena.allocate(skLen);
            int rc = (int) CrystalsLib.KYBER_KEYGEN.invokeExact(
                level, pk, pkLen, sk, skLen);
            CrystalsLib.checkResult(rc, "kyber_keygen");
            return new KeyPair(pk.toArray(ValueLayout.JAVA_BYTE),
                               sk.toArray(ValueLayout.JAVA_BYTE));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("kyber_keygen failed", t);
        }
    }

    public static EncapsResult encaps(int level, byte[] pk) {
        try (Arena arena = Arena.ofConfined()) {
            long pkLen = pkBytes(level);
            long ctLen = ctBytes(level);
            MemorySegment pkSeg = arena.allocate(pkLen);
            MemorySegment.copy(MemorySegment.ofArray(pk), 0, pkSeg, 0, pkLen);
            MemorySegment ctSeg = arena.allocate(ctLen);
            MemorySegment ssSeg = arena.allocate(SS_BYTES);
            int rc = (int) CrystalsLib.KYBER_ENCAPS.invokeExact(
                level, pkSeg, pkLen, ctSeg, ctLen, ssSeg, (long) SS_BYTES);
            CrystalsLib.checkResult(rc, "kyber_encaps");
            return new EncapsResult(ctSeg.toArray(ValueLayout.JAVA_BYTE),
                                    ssSeg.toArray(ValueLayout.JAVA_BYTE));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("kyber_encaps failed", t);
        }
    }

    public static byte[] decaps(int level, byte[] sk, byte[] ct) {
        try (Arena arena = Arena.ofConfined()) {
            long skLen = skBytes(level);
            long ctLen = ctBytes(level);
            MemorySegment skSeg = arena.allocate(skLen);
            MemorySegment.copy(MemorySegment.ofArray(sk), 0, skSeg, 0, skLen);
            MemorySegment ctSeg = arena.allocate(ctLen);
            MemorySegment.copy(MemorySegment.ofArray(ct), 0, ctSeg, 0, ctLen);
            MemorySegment ssSeg = arena.allocate(SS_BYTES);
            int rc = (int) CrystalsLib.KYBER_DECAPS.invokeExact(
                level, skSeg, skLen, ctSeg, ctLen, ssSeg, (long) SS_BYTES);
            CrystalsLib.checkResult(rc, "kyber_decaps");
            return ssSeg.toArray(ValueLayout.JAVA_BYTE);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("kyber_decaps failed", t);
        }
    }

    public static int pkBytes(int level) {
        try {
            return (int)(long) CrystalsLib.KYBER_PK_BYTES.invokeExact(level);
        } catch (Throwable t) { throw new CrystalsException("kyber_pk_bytes", t); }
    }
    public static int skBytes(int level) {
        try {
            return (int)(long) CrystalsLib.KYBER_SK_BYTES.invokeExact(level);
        } catch (Throwable t) { throw new CrystalsException("kyber_sk_bytes", t); }
    }
    public static int ctBytes(int level) {
        try {
            return (int)(long) CrystalsLib.KYBER_CT_BYTES.invokeExact(level);
        } catch (Throwable t) { throw new CrystalsException("kyber_ct_bytes", t); }
    }

    private KyberKEM() {}
}
