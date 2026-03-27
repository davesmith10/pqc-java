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
