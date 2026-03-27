package pqc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.*;
import java.util.concurrent.TimeUnit;

class McElieceKEMTest {

    /* Only the smallest variant is practical in a test suite — keygen is slow */
    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void roundtrip_348864f() {
        var alg = McElieceKEM.Algorithm.MCELIECE_348864F;
        var kp  = McElieceKEM.keygen(alg);
        var enc = McElieceKEM.encaps(alg, kp.pk());
        var ss  = McElieceKEM.decaps(alg, kp.sk(), enc.ct());
        assertArrayEquals(enc.ss(), ss, "shared secrets must match");
        assertEquals(McElieceKEM.SS_BYTES, ss.length);
    }
}
