package pqc;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class KyberKEMTest {

    @ParameterizedTest
    @ValueSource(ints = {512, 768, 1024})
    void roundtrip(int level) {
        var kp  = KyberKEM.keygen(level);
        var enc = KyberKEM.encaps(level, kp.pk());
        var ss  = KyberKEM.decaps(level, kp.sk(), enc.ct());
        assertArrayEquals(enc.ss(), ss, "shared secrets must match for level " + level);
    }

    @Test
    void invalidLevelThrows() {
        assertThrows(IllegalArgumentException.class, () -> KyberKEM.keygen(999));
    }

    @Test
    void ssBytesIs32() {
        assertEquals(32, KyberKEM.SS_BYTES);
    }
}
