package pqc;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class OqsKEMTest {

    @ParameterizedTest
    @EnumSource(OqsKEM.Algorithm.class)
    void roundtrip(OqsKEM.Algorithm alg) {
        var kp  = OqsKEM.keygen(alg);
        var enc = OqsKEM.encaps(alg, kp.pk());
        var ss  = OqsKEM.decaps(alg, kp.sk(), enc.ct());
        assertArrayEquals(enc.ss(), ss, "shared secrets must match for " + alg);
        assertEquals(OqsKEM.ssBytes(alg), ss.length);
    }
}
