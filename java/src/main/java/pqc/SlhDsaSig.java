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
