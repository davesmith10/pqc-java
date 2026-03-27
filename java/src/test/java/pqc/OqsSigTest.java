package pqc;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class OqsSigTest {

    private static final byte[] MSG     = "hello post-quantum world".getBytes();
    private static final byte[] BAD_MSG = "hello post-quantum WORLD".getBytes();

    @ParameterizedTest
    @EnumSource(OqsSig.Algorithm.class)
    void roundtrip(OqsSig.Algorithm alg) {
        var kp  = OqsSig.keygen(alg);
        var sig = OqsSig.sign(alg, kp.sk(), MSG);

        // Falcon sigs are variable-length; ML-DSA sigs are fixed
        assertTrue(sig.length > 0, "sig must be non-empty for " + alg);
        assertTrue(sig.length <= OqsSig.sigBytes(alg),
            "sig length must not exceed max for " + alg);

        assertTrue(OqsSig.verify(alg, kp.pk(), MSG, sig),
            "valid sig must verify for " + alg);
        assertFalse(OqsSig.verify(alg, kp.pk(), BAD_MSG, sig),
            "tampered msg must not verify for " + alg);
    }
}
