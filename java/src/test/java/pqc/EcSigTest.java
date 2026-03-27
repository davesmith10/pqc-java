package pqc;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class EcSigTest {

    private static final byte[] MSG     = "hello post-quantum world".getBytes();
    private static final byte[] BAD_MSG = "hello post-quantum WORLD".getBytes();

    @ParameterizedTest
    @EnumSource(EcSig.Algorithm.class)
    void roundtrip(EcSig.Algorithm alg) {
        var kp  = EcSig.keygen(alg);
        var sig = EcSig.sign(alg, kp.sk(), MSG);
        assertTrue(EcSig.verify(alg, kp.pk(), MSG, sig),
            "valid sig must verify for " + alg);
        assertFalse(EcSig.verify(alg, kp.pk(), BAD_MSG, sig),
            "tampered msg must not verify for " + alg);
    }
}
