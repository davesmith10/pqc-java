package pqc;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class EcKEMTest {

    @ParameterizedTest
    @EnumSource(EcKEM.Algorithm.class)
    void roundtrip(EcKEM.Algorithm alg) {
        var kp  = EcKEM.keygen(alg);
        var enc = EcKEM.encaps(alg, kp.pk());
        var ss  = EcKEM.decaps(alg, kp.sk(), enc.ct());
        assertArrayEquals(enc.ss(), ss, "shared secrets must match for " + alg);
    }
}
