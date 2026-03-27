package pqc;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class DilithiumSigTest {

    private static final byte[] MSG     = "hello post-quantum world".getBytes();
    private static final byte[] BAD_MSG = "hello post-quantum WORLD".getBytes();

    @ParameterizedTest
    @ValueSource(ints = {2, 3, 5})
    void roundtrip(int mode) {
        var kp  = DilithiumSig.keygen(mode);
        var sig = DilithiumSig.sign(mode, kp.sk(), MSG);
        assertTrue(DilithiumSig.verify(mode, kp.pk(), MSG, sig),
            "valid sig must verify for mode " + mode);
        assertFalse(DilithiumSig.verify(mode, kp.pk(), BAD_MSG, sig),
            "tampered msg must not verify for mode " + mode);
    }
}
