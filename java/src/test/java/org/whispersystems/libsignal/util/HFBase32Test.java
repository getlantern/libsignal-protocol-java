package org.whispersystems.libsignal.util;

import junit.framework.TestCase;

import org.junit.BeforeClass;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class HFBase32Test extends TestCase {
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
            byte[] encoded = HFBase32.encode(string.getBytes(StandardCharsets.UTF_8));
            System.out.println(new String(encoded, StandardCharsets.UTF_8));
            String roundTripped = new String(HFBase32.decode(encoded));
            assertEquals(string, roundTripped);
        }
    }

    public void testRoundTripBytes() {
        byte[] b = new byte[0];
        for (int i = 0; i < 255; i++) {
            b = Arrays.copyOf(b, b.length + 1);
            b[i] = (byte) i;
            byte[] encoded = HFBase32.encode(b);
            System.out.println(new String(encoded));
            byte[] roundTripped = HFBase32.decode(encoded);
            assertTrue(Arrays.equals(b, roundTripped));
        }
    }

    public void testDecodeNullString() {
        assertNotNull(HFBase32.decode((String) null));
    }

    public void testDecodeNullBytes() {
        assertNotNull(HFBase32.decode((byte[]) null));
    }

    /**
     * This test verifies that special character replacements are handled correctly. Namely:
     *
     * i -> 1
     * l -> 1
     * 0 -> o
     */
    public void testDecodeSpecialCharacters() {
        String normal = "y100";
        assertEquals(
                new String(HFBase32.decode(normal.getBytes(StandardCharsets.UTF_8))),
                new String(HFBase32.decode("yioo"))
        );
        assertEquals(
                new String(HFBase32.decode(normal.getBytes(StandardCharsets.UTF_8))),
                new String(HFBase32.decode("yloo"))
        );
        assertEquals(
                new String(HFBase32.decode(normal.getBytes(StandardCharsets.UTF_8))),
                new String(HFBase32.decode("y1o0"))
        );
    }

    public void testAgainstTestVectors() {
        for (Map.Entry<String, String> entry : testVectors.entrySet()) {
            byte[] encoded = HFBase32.encode(entry.getKey().getBytes(StandardCharsets.UTF_8));
            assertEquals(entry.getValue(), new String(encoded, StandardCharsets.UTF_8));
        }
    }

    // XXX <12-01-22> soltzen: leaving this commented test here as a precaution
    // for no one to attempt this: Java's GC prevents very accurate measurements
    // of data. There must be a good way to measure constant-time crypto.
    // For reference, most big crypto repos don't test execution time with their
    // constant-time code:
    // - Libsodium's sodium_memcmp and sodium_hex2bin:
    //   https://github.com/jedisct1/libsodium/blob/6d566070b48efd2fa099bbe9822914455150aba9/test/default/verify1.c
    // - The entire crypto/subtle Golang package: https://pkg.go.dev/crypto/subtle
    //
    // A good test here is to measure the standard deviation between two sets of
    // time differences: one with constant-time zbase32 and one without. The
    // latter's SD would be a lot higher
    // public void testConstantTime() {
    //     SecureRandom random = new SecureRandom();
    //     for (int i = 0; i < 10; i++) {
    //         Set<Long> encodingTimes = new HashSet<>();
    //         int size = random.nextInt(10000);
    //         // Encode 10 random strings with the same length
    //         for (int j = 0; j < 10; j++) {
    //             byte[] b = new byte[size];
    //             random.nextBytes(b);
    //             long startTime = System.nanoTime();
    //             HFBase32.encode(b);
    //             long endTime = System.nanoTime();
    //             encodingTimes.add(endTime - startTime);
    //         }
    //         System.out.println(encodingTimes);
    //         assertEquals(1, encodingTimes.size());
    //     }
    // }
}
