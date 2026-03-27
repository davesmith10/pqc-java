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
