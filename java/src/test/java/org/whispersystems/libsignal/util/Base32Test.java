package org.whispersystems.libsignal.util;

import junit.framework.TestCase;

import org.junit.BeforeClass;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Base32Test extends TestCase {
    // Contains a list of strings encoded with other encoders in order to have a unified source of truth
    Map<String, String> testVectors = new HashMap<String, String>();

    @BeforeClass
    public void setUp() {
        // Taken from [here](https://www.dcode.fr/z-base-32-encoding), after
        // changing all i's to 2's, as we do in our algorithm.
        testVectors.put("foo", "c3zs6");
        testVectors.put("foob", "c3zs6ao");
        testVectors.put("fooba", "c3zs6aub");
        testVectors.put("foobar", "c3zs6aubqe");
        testVectors.put("foobar", "c3zs6aubqe");
        testVectors.put(
                "thegrowingdoubtofhumanautonomyandreasonhascreatedastateofmoralconfusionwheremanisleftwithouttheguidanceofeitherrevelationorreasontheresultistheacceptanceofarelativisticpositionwhichproposesthatvaluejudgementsandethicalnormsareexclusivelymattersofarbitrarypreferenceandthatnoobjectivelyvalidstatementcanbemadeinthisrealmbutsincemancannotlivewithoutvaluesandnormsthisrelativismmakeshimaneasypreyforirrationalvaluesystems",
                "qtwgk351p75s15u8ctzzkauwp7ugo7mpcfzgn7mwp7zg65m3cfzgehufcf3s65uecf3sghufcf4gk3dbqp4gn7dfp7ug4551cfsgg55qc34zg4mxp35so3m1c2ssn5ujqpsgk3uwq7wze4dxq248e4dfc74s13dbp3tsk55gc2wze4dfqj3gk7ufptoze4mxp3zzrhufcf3s65uwpb1zr3muq2s8e4muqtwgkamdcp1zy7dbp3tsk55gcf3gk5dbqtwzc4muqtwsghdxqpwze4mxp35so4mdpba8r55op73skh5wpboze7ubpt4sk4u2ctusk5mfp348gamqct1ze4djcposa5uxqjszgam1c21zoa5cq23s17ufpths4amwqt1zrh5xc3ozraujqt3gnhu3qb3gk3ufqj1sha5fcfzge7decf4gh55xcj2gka5wpf5gk5d3q3osa4mrqp4gn7dfp21sh7ddcfzgr3mpcf1gk4mqqtwg1h51c2osa5mnq248g4mqcp1s4amqcposh5uxqtsg17ufq7wze4dxq248camcq21zgamqctzg6hupqp4go4muqj1saamwpf5g1h5pp2oss3mupbws4amqc2ozg6moqj1z13uxqjwzrhubqtws65ubpt5gn5d2c23z1h5wc2szg");
    }

    public void testRoundTripString() {
        for (int i = 1; i < 128; i++) {
            StringBuilder builder = new StringBuilder(i);
            for (int j = 0; j < i; j++) {
                builder.append(j);
            }
            String string = builder.toString();
            byte[] encoded = Base32.encode(string.getBytes(StandardCharsets.UTF_8));
            System.out.println(new String(encoded, StandardCharsets.UTF_8));
            String roundTripped = new String(Base32.decode(encoded));
            assertEquals(string, roundTripped);
        }
    }

    public void testRoundTripBytes() {
        byte[] b = new byte[0];
        for (int i = 0; i < 255; i++) {
            b = Arrays.copyOf(b, b.length + 1);
            b[i] = (byte) i;
            byte[] encoded = Base32.encode(b);
            System.out.println(new String(encoded));
            byte[] roundTripped = Base32.decode(encoded);
            assertTrue(Arrays.equals(b, roundTripped));
        }
    }

    public void testDecodeNullString() {
        assertNotNull(Base32.decode((String) null));
    }

    public void testDecodeNullBytes() {
        assertNotNull(Base32.decode((byte[]) null));
    }

    public void testDecodeSpecialCharacters() {
        String normal = "y100";
        assertEquals(
                new String(Base32.decode(normal.getBytes(StandardCharsets.UTF_8))),
                new String(Base32.decode("yi00")));
        assertEquals(
                new String(Base32.decode(normal.getBytes(StandardCharsets.UTF_8))),
                new String(Base32.decode("yl00")));
        assertEquals(
                new String(Base32.decode(normal.getBytes(StandardCharsets.UTF_8))),
                new String(Base32.decode("y1oo")));
    }

    public void testWithTestVectors() {
        for (Map.Entry<String, String> entry : testVectors.entrySet()) {
            long startTime = System.nanoTime();
            byte[] encoded = Base32.encode(entry.getKey().getBytes(StandardCharsets.UTF_8));
            long endTime = System.nanoTime();
            System.out.println(endTime - startTime);
            assertEquals(entry.getValue(), new String(encoded, StandardCharsets.UTF_8));
        }
    }

}
