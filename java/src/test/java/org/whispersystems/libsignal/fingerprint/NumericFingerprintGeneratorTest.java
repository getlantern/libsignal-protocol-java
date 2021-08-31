package org.whispersystems.libsignal.fingerprint;

import junit.framework.TestCase;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.util.Arrays;

public class NumericFingerprintGeneratorTest extends TestCase {

  private static final byte[] ALICE_IDENTITY = {(byte) 0x06, (byte) 0x86, (byte) 0x3b, (byte) 0xc6, (byte) 0x6d, (byte) 0x02, (byte) 0xb4, (byte) 0x0d, (byte) 0x27, (byte) 0xb8, (byte) 0xd4, (byte) 0x9c, (byte) 0xa7, (byte) 0xc0, (byte) 0x9e, (byte) 0x92, (byte) 0x39, (byte) 0x23, (byte) 0x6f, (byte) 0x9d, (byte) 0x7d, (byte) 0x25, (byte) 0xd6, (byte) 0xfc, (byte) 0xca, (byte) 0x5c, (byte) 0xe1, (byte) 0x3c, (byte) 0x70, (byte) 0x64, (byte) 0xd8, (byte) 0x68};
  private static final byte[] BOB_IDENTITY   = {(byte) 0xf7, (byte) 0x81, (byte) 0xb6, (byte) 0xfb, (byte) 0x32, (byte) 0xfe, (byte) 0xd9, (byte) 0xba, (byte) 0x1c, (byte) 0xf2, (byte) 0xde, (byte) 0x97, (byte) 0x8d, (byte) 0x4d, (byte) 0x5d, (byte) 0xa2, (byte) 0x8d, (byte) 0xc3, (byte) 0x40, (byte) 0x46, (byte) 0xae, (byte) 0x81, (byte) 0x44, (byte) 0x02, (byte) 0xb5, (byte) 0xc0, (byte) 0xdb, (byte) 0xd9, (byte) 0x6f, (byte) 0xda, (byte) 0x90, (byte) 0x7b};

  private static final int    VERSION_1                      = 1;
  private static final String DISPLAYABLE_FINGERPRINT_V1     = "059142880471735069831131731564940027731022934467570443017412";
  private static final byte[] ALICE_SCANNABLE_FINGERPRINT_V1 = new byte[]{(byte)0x08, (byte)0x01, (byte)0x12, (byte)0x22, (byte)0x0a, (byte)0x20, (byte)0xd4, (byte)0x7b, (byte)0x01, (byte)0xfa, (byte)0x92, (byte)0x28, (byte)0xc1, (byte)0x07, (byte)0x5d, (byte)0xde, (byte)0x7e, (byte)0x90, (byte)0x51, (byte)0x3e, (byte)0xf6, (byte)0xdc, (byte)0x75, (byte)0x74, (byte)0x14, (byte)0x45, (byte)0x13, (byte)0x23, (byte)0x58, (byte)0xdb, (byte)0x0e, (byte)0xc9, (byte)0xed, (byte)0x8c, (byte)0x3d, (byte)0x44, (byte)0xda, (byte)0x16, (byte)0x1a, (byte)0x22, (byte)0x0a, (byte)0x20, (byte)0x27, (byte)0x08, (byte)0xe4, (byte)0x53, (byte)0xba, (byte)0x25, (byte)0x90, (byte)0x14, (byte)0x23, (byte)0x44, (byte)0x48, (byte)0x63, (byte)0xa7, (byte)0x92, (byte)0x97, (byte)0x5c, (byte)0xdd, (byte)0x8b, (byte)0xa2, (byte)0x27, (byte)0x5e, (byte)0xfd, (byte)0x17, (byte)0xa6, (byte)0x15, (byte)0x07, (byte)0x05, (byte)0x02, (byte)0xa9, (byte)0x4c, (byte)0x79, (byte)0xd4};
  private static final byte[] BOB_SCANNABLE_FINGERPRINT_V1   = new byte[]{(byte)0x08, (byte)0x01, (byte)0x12, (byte)0x22, (byte)0x0a, (byte)0x20, (byte)0x27, (byte)0x08, (byte)0xe4, (byte)0x53, (byte)0xba, (byte)0x25, (byte)0x90, (byte)0x14, (byte)0x23, (byte)0x44, (byte)0x48, (byte)0x63, (byte)0xa7, (byte)0x92, (byte)0x97, (byte)0x5c, (byte)0xdd, (byte)0x8b, (byte)0xa2, (byte)0x27, (byte)0x5e, (byte)0xfd, (byte)0x17, (byte)0xa6, (byte)0x15, (byte)0x07, (byte)0x05, (byte)0x02, (byte)0xa9, (byte)0x4c, (byte)0x79, (byte)0xd4, (byte)0x1a, (byte)0x22, (byte)0x0a, (byte)0x20, (byte)0xd4, (byte)0x7b, (byte)0x01, (byte)0xfa, (byte)0x92, (byte)0x28, (byte)0xc1, (byte)0x07, (byte)0x5d, (byte)0xde, (byte)0x7e, (byte)0x90, (byte)0x51, (byte)0x3e, (byte)0xf6, (byte)0xdc, (byte)0x75, (byte)0x74, (byte)0x14, (byte)0x45, (byte)0x13, (byte)0x23, (byte)0x58, (byte)0xdb, (byte)0x0e, (byte)0xc9, (byte)0xed, (byte)0x8c, (byte)0x3d, (byte)0x44, (byte)0xda, (byte)0x16};

  private static final int    VERSION_2                      = 2;
  private static final String DISPLAYABLE_FINGERPRINT_V2     = DISPLAYABLE_FINGERPRINT_V1;
  private static final byte[] ALICE_SCANNABLE_FINGERPRINT_V2 = new byte[]{(byte)0x08, (byte)0x02, (byte)0x12, (byte)0x22, (byte)0x0a, (byte)0x20, (byte)0xd4, (byte)0x7b, (byte)0x01, (byte)0xfa, (byte)0x92, (byte)0x28, (byte)0xc1, (byte)0x07, (byte)0x5d, (byte)0xde, (byte)0x7e, (byte)0x90, (byte)0x51, (byte)0x3e, (byte)0xf6, (byte)0xdc, (byte)0x75, (byte)0x74, (byte)0x14, (byte)0x45, (byte)0x13, (byte)0x23, (byte)0x58, (byte)0xdb, (byte)0x0e, (byte)0xc9, (byte)0xed, (byte)0x8c, (byte)0x3d, (byte)0x44, (byte)0xda, (byte)0x16, (byte)0x1a, (byte)0x22, (byte)0x0a, (byte)0x20, (byte)0x27, (byte)0x08, (byte)0xe4, (byte)0x53, (byte)0xba, (byte)0x25, (byte)0x90, (byte)0x14, (byte)0x23, (byte)0x44, (byte)0x48, (byte)0x63, (byte)0xa7, (byte)0x92, (byte)0x97, (byte)0x5c, (byte)0xdd, (byte)0x8b, (byte)0xa2, (byte)0x27, (byte)0x5e, (byte)0xfd, (byte)0x17, (byte)0xa6, (byte)0x15, (byte)0x07, (byte)0x05, (byte)0x02, (byte)0xa9, (byte)0x4c, (byte)0x79, (byte)0xd4};
  private static final byte[] BOB_SCANNABLE_FINGERPRINT_V2   = new byte[]{(byte)0x08, (byte)0x02, (byte)0x12, (byte)0x22, (byte)0x0a, (byte)0x20, (byte)0x27, (byte)0x08, (byte)0xe4, (byte)0x53, (byte)0xba, (byte)0x25, (byte)0x90, (byte)0x14, (byte)0x23, (byte)0x44, (byte)0x48, (byte)0x63, (byte)0xa7, (byte)0x92, (byte)0x97, (byte)0x5c, (byte)0xdd, (byte)0x8b, (byte)0xa2, (byte)0x27, (byte)0x5e, (byte)0xfd, (byte)0x17, (byte)0xa6, (byte)0x15, (byte)0x07, (byte)0x05, (byte)0x02, (byte)0xa9, (byte)0x4c, (byte)0x79, (byte)0xd4, (byte)0x1a, (byte)0x22, (byte)0x0a, (byte)0x20, (byte)0xd4, (byte)0x7b, (byte)0x01, (byte)0xfa, (byte)0x92, (byte)0x28, (byte)0xc1, (byte)0x07, (byte)0x5d, (byte)0xde, (byte)0x7e, (byte)0x90, (byte)0x51, (byte)0x3e, (byte)0xf6, (byte)0xdc, (byte)0x75, (byte)0x74, (byte)0x14, (byte)0x45, (byte)0x13, (byte)0x23, (byte)0x58, (byte)0xdb, (byte)0x0e, (byte)0xc9, (byte)0xed, (byte)0x8c, (byte)0x3d, (byte)0x44, (byte)0xda, (byte)0x16};

  public void testVectorsVersion1() throws Exception {
    ECPublicKey aliceIdentityKey = new ECPublicKey(ALICE_IDENTITY);
    ECPublicKey bobIdentityKey   = new ECPublicKey(BOB_IDENTITY);
    byte[]      aliceStableId    = "+14152222222".getBytes();
    byte[]      bobStableId      = "+14153333333".getBytes();

    NumericFingerprintGenerator generator = new NumericFingerprintGenerator(5200);

    Fingerprint aliceFingerprint = generator.createFor(VERSION_1,
                                                      aliceStableId, aliceIdentityKey,
                                                      bobStableId, bobIdentityKey);

    Fingerprint bobFingerprint = generator.createFor(VERSION_1,
                                                     bobStableId, bobIdentityKey,
                                                     aliceStableId, aliceIdentityKey);

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT_V1);
    assertEquals(bobFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT_V1);

    assertTrue(Arrays.equals(aliceFingerprint.getScannableFingerprint().getSerialized(), ALICE_SCANNABLE_FINGERPRINT_V1));
    assertTrue(Arrays.equals(bobFingerprint.getScannableFingerprint().getSerialized(), BOB_SCANNABLE_FINGERPRINT_V1));
  }

  public void testVectorsVersion2() throws Exception {
    ECPublicKey aliceIdentityKey = new ECPublicKey(ALICE_IDENTITY);
    ECPublicKey bobIdentityKey   = new ECPublicKey(BOB_IDENTITY);
    byte[]      aliceStableId    = "+14152222222".getBytes();
    byte[]      bobStableId      = "+14153333333".getBytes();

    NumericFingerprintGenerator generator = new NumericFingerprintGenerator(5200);

    Fingerprint aliceFingerprint = generator.createFor(VERSION_2,
                                                      aliceStableId, aliceIdentityKey,
                                                      bobStableId, bobIdentityKey);

    Fingerprint bobFingerprint = generator.createFor(VERSION_2,
                                                     bobStableId, bobIdentityKey,
                                                     aliceStableId, aliceIdentityKey);

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT_V2);
    assertEquals(bobFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT_V2);

    assertTrue(Arrays.equals(aliceFingerprint.getScannableFingerprint().getSerialized(), ALICE_SCANNABLE_FINGERPRINT_V2));
    assertTrue(Arrays.equals(bobFingerprint.getScannableFingerprint().getSerialized(), BOB_SCANNABLE_FINGERPRINT_V2));
  }

  public void testMatchingFingerprints() throws FingerprintVersionMismatchException, FingerprintIdentifierMismatchException, FingerprintParsingException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair   = Curve.generateKeyPair();

    ECPublicKey aliceIdentityKey = aliceKeyPair.getPublicKey();
    ECPublicKey bobIdentityKey   = bobKeyPair.getPublicKey();

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(1024);
    Fingerprint                 aliceFingerprint = generator.createFor(VERSION_1,
                                                                       "+14152222222".getBytes(), aliceIdentityKey,
                                                                       "+14153333333".getBytes(), bobIdentityKey);

    Fingerprint bobFingerprint = generator.createFor(VERSION_1,
                                                     "+14153333333".getBytes(), bobIdentityKey,
                                                     "+14152222222".getBytes(), aliceIdentityKey);

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                 bobFingerprint.getDisplayableFingerprint().getDisplayText());

    assertTrue(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertTrue(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText().length(), 60);
  }

  public void testMismatchingFingerprints() throws FingerprintVersionMismatchException, FingerprintIdentifierMismatchException, FingerprintParsingException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair   = Curve.generateKeyPair();
    ECKeyPair mitmKeyPair  = Curve.generateKeyPair();

    ECPublicKey aliceIdentityKey = aliceKeyPair.getPublicKey();
    ECPublicKey bobIdentityKey   = bobKeyPair.getPublicKey();
    ECPublicKey mitmIdentityKey  = mitmKeyPair.getPublicKey();

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(1024);
    Fingerprint                 aliceFingerprint = generator.createFor(VERSION_1,
                                                                       "+14152222222".getBytes(), aliceIdentityKey,
                                                                       "+14153333333".getBytes(), mitmIdentityKey);

    Fingerprint bobFingerprint = generator.createFor(VERSION_1,
                                                     "+14153333333".getBytes(), bobIdentityKey,
                                                     "+14152222222".getBytes(), aliceIdentityKey);

    assertFalse(aliceFingerprint.getDisplayableFingerprint().getDisplayText().equals(
                bobFingerprint.getDisplayableFingerprint().getDisplayText()));

    assertFalse(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertFalse(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));
  }

  public void testMismatchingIdentifiers() throws FingerprintVersionMismatchException, FingerprintParsingException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair   = Curve.generateKeyPair();

    ECPublicKey aliceIdentityKey = aliceKeyPair.getPublicKey();
    ECPublicKey bobIdentityKey   = bobKeyPair.getPublicKey();

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(1024);
    Fingerprint                 aliceFingerprint = generator.createFor(VERSION_1,
                                                                       "+141512222222".getBytes(), aliceIdentityKey,
                                                                       "+14153333333".getBytes(), bobIdentityKey);

    Fingerprint bobFingerprint = generator.createFor(VERSION_1,
                                                     "+14153333333".getBytes(), bobIdentityKey,
                                                     "+14152222222".getBytes(), aliceIdentityKey);

    assertFalse(aliceFingerprint.getDisplayableFingerprint().getDisplayText().equals(
                bobFingerprint.getDisplayableFingerprint().getDisplayText()));

    assertFalse(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertFalse(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));
  }

  public void testDifferentVersionsMakeSameFingerPrintsButDifferentScannable() throws Exception {
    ECPublicKey aliceIdentityKey = new ECPublicKey(ALICE_IDENTITY);
    ECPublicKey bobIdentityKey   = new ECPublicKey(BOB_IDENTITY);
    byte[]      aliceStableId    = "+14152222222".getBytes();
    byte[]      bobStableId      = "+14153333333".getBytes();

    NumericFingerprintGenerator generator          = new NumericFingerprintGenerator(5200);

    Fingerprint aliceFingerprintV1 = generator.createFor(VERSION_1,
                                                         aliceStableId, aliceIdentityKey,
                                                         bobStableId, bobIdentityKey);

    Fingerprint aliceFingerprintV2 = generator.createFor(VERSION_2,
                                                         aliceStableId, aliceIdentityKey,
                                                         bobStableId, bobIdentityKey);


    assertTrue(aliceFingerprintV1.getDisplayableFingerprint().getDisplayText().equals(
               aliceFingerprintV2.getDisplayableFingerprint().getDisplayText()));

    assertFalse(Arrays.equals(aliceFingerprintV1.getScannableFingerprint().getSerialized(),
                              aliceFingerprintV2.getScannableFingerprint().getSerialized()));
  }

}
