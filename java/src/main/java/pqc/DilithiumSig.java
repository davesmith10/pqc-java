package pqc;

import java.lang.foreign.*;

/**
 * Dilithium (ML-DSA) signatures at modes 2, 3, and 5.
 */
public final class DilithiumSig {

    public record KeyPair(byte[] pk, byte[] sk) {}

    public static KeyPair keygen(int mode) {
        try (Arena arena = Arena.ofConfined()) {
            long pkLen = pkBytes(mode);
            long skLen = skBytes(mode);
            MemorySegment pk = arena.allocate(pkLen);
            MemorySegment sk = arena.allocate(skLen);
            int rc = (int) CrystalsLib.DILITHIUM_KEYGEN.invokeExact(
                mode, pk, pkLen, sk, skLen);
            CrystalsLib.checkResult(rc, "dilithium_keygen");
            return new KeyPair(pk.toArray(ValueLayout.JAVA_BYTE),
                               sk.toArray(ValueLayout.JAVA_BYTE));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("dilithium_keygen failed", t);
        }
    }

    public static byte[] sign(int mode, byte[] sk, byte[] msg) {
        try (Arena arena = Arena.ofConfined()) {
            long skLen  = skBytes(mode);
            long sigLen = sigBytes(mode);
            MemorySegment skSeg  = arena.allocate(skLen);
            MemorySegment.copy(MemorySegment.ofArray(sk), 0, skSeg, 0, skLen);
            MemorySegment msgSeg = arena.allocate(msg.length);
            MemorySegment.copy(MemorySegment.ofArray(msg), 0, msgSeg, 0, msg.length);
            MemorySegment sigSeg = arena.allocate(sigLen);
            int rc = (int) CrystalsLib.DILITHIUM_SIGN.invokeExact(
                mode, skSeg, skLen, msgSeg, (long) msg.length, sigSeg, sigLen);
            CrystalsLib.checkResult(rc, "dilithium_sign");
            return sigSeg.toArray(ValueLayout.JAVA_BYTE);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("dilithium_sign failed", t);
        }
    }

    public static boolean verify(int mode, byte[] pk, byte[] msg, byte[] sig) {
        try (Arena arena = Arena.ofConfined()) {
            long pkLen  = pkBytes(mode);
            long sigLen = sigBytes(mode);
            MemorySegment pkSeg  = arena.allocate(pkLen);
            MemorySegment.copy(MemorySegment.ofArray(pk), 0, pkSeg, 0, pkLen);
            MemorySegment msgSeg = arena.allocate(msg.length);
            MemorySegment.copy(MemorySegment.ofArray(msg), 0, msgSeg, 0, msg.length);
            MemorySegment sigSeg = arena.allocate(sigLen);
            MemorySegment.copy(MemorySegment.ofArray(sig), 0, sigSeg, 0,
                Math.min(sig.length, sigLen));
            int rc = (int) CrystalsLib.DILITHIUM_VERIFY.invokeExact(
                mode, pkSeg, pkLen, msgSeg, (long) msg.length, sigSeg, sigLen);
            if (rc == CrystalsLib.ECRYPTO) return false;
            CrystalsLib.checkResult(rc, "dilithium_verify");
            return true;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("dilithium_verify failed", t);
        }
    }

    public static int pkBytes(int mode) {
        try {
            int v = (int)(long) CrystalsLib.DILITHIUM_PK_BYTES.invokeExact(mode);
            if (v == 0) throw new IllegalArgumentException("dilithium_pk_bytes: unknown mode " + mode);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("dilithium_pk_bytes", t); }
    }

    public static int skBytes(int mode) {
        try {
            int v = (int)(long) CrystalsLib.DILITHIUM_SK_BYTES.invokeExact(mode);
            if (v == 0) throw new IllegalArgumentException("dilithium_sk_bytes: unknown mode " + mode);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("dilithium_sk_bytes", t); }
    }

    public static int sigBytes(int mode) {
        try {
            int v = (int)(long) CrystalsLib.DILITHIUM_SIG_BYTES.invokeExact(mode);
            if (v == 0) throw new IllegalArgumentException("dilithium_sig_bytes: unknown mode " + mode);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("dilithium_sig_bytes", t); }
    }

    private DilithiumSig() {}
}
