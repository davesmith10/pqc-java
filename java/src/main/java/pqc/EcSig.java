package pqc;

import java.lang.foreign.*;

/**
 * EC signatures: Ed25519 and ECDSA over P-256, P-384, and P-521.
 */
public final class EcSig {

    public enum Algorithm {
        Ed25519, P256, P384, P521;

        String cName() {
            return switch (this) {
                case Ed25519 -> "Ed25519";
                case P256    -> "ECDSA P-256";
                case P384    -> "ECDSA P-384";
                case P521    -> "ECDSA P-521";
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
            int rc = (int) CrystalsLib.EC_SIG_KEYGEN.invokeExact(
                algSeg, pk, pkLen, sk, skLen);
            CrystalsLib.checkResult(rc, "ec_sig_keygen");
            return new KeyPair(pk.toArray(ValueLayout.JAVA_BYTE),
                               sk.toArray(ValueLayout.JAVA_BYTE));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("ec_sig_keygen failed", t);
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
            int rc = (int) CrystalsLib.EC_SIG_SIGN.invokeExact(
                algSeg, skSeg, skLen, msgSeg, (long) msg.length, sigSeg, sigLen);
            CrystalsLib.checkResult(rc, "ec_sig_sign");
            return sigSeg.toArray(ValueLayout.JAVA_BYTE);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("ec_sig_sign failed", t);
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
            int rc = (int) CrystalsLib.EC_SIG_VERIFY.invokeExact(
                algSeg, pkSeg, pkLen, msgSeg, (long) msg.length, sigSeg, sigLen);
            if (rc == CrystalsLib.ECRYPTO) return false;
            CrystalsLib.checkResult(rc, "ec_sig_verify");
            return true;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new CrystalsException("ec_sig_verify failed", t);
        }
    }

    public static int pkBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.EC_SIG_PK_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("ec_sig_pk_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("ec_sig_pk_bytes", t); }
    }

    public static int skBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.EC_SIG_SK_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("ec_sig_sk_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("ec_sig_sk_bytes", t); }
    }

    public static int sigBytes(Algorithm alg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment algSeg = arena.allocateUtf8String(alg.cName());
            int v = (int)(long) CrystalsLib.EC_SIG_BYTES.invokeExact(algSeg);
            if (v == 0) throw new IllegalArgumentException("ec_sig_bytes: unknown alg " + alg);
            return v;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) { throw new CrystalsException("ec_sig_bytes", t); }
    }

    private EcSig() {}
}
