package pqc;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class SlhDsaTest {

    private static final byte[] MSG     = "hello post-quantum world".getBytes();
    private static final byte[] BAD_MSG = "hello post-quantum WORLD".getBytes();

    @ParameterizedTest
    @EnumSource(SlhDsaSig.Algorithm.class)
    void roundtrip(SlhDsaSig.Algorithm alg) {
        var kp  = SlhDsaSig.keygen(alg);
        var sig = SlhDsaSig.sign(alg, kp.sk(), MSG);
        assertTrue(SlhDsaSig.verify(alg, kp.pk(), MSG, sig),
            "valid sig must verify for " + alg);
        assertFalse(SlhDsaSig.verify(alg, kp.pk(), BAD_MSG, sig),
            "tampered msg must not verify for " + alg);
    }
}
