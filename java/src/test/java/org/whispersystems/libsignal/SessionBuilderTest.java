package org.whispersystems.libsignal;

import junit.framework.TestCase;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.Pair;

import java.util.HashSet;
import java.util.Set;

public class SessionBuilderTest extends TestCase {

  public void testBasicPreKeyV2()
      throws InvalidKeyException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, NoSessionException {
    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

    SignalProtocolAddress bobAddress = new SignalProtocolAddress(bobStore.getIdentityKeyPair().getPublicKey(), DeviceId.random());
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, bobAddress);

    ECKeyPair    bobPreKeyPair = Curve.generateKeyPair();
    PreKeyBundle bobPreKey     = new PreKeyBundle(31337, bobPreKeyPair.getPublicKey(),
                                                  0, null, null,
                                                  bobStore.getIdentityKeyPair().getPublicKey());

    try {
      aliceSessionBuilder.process(bobPreKey);
      throw new AssertionError("Should fail with missing unsigned prekey!");
    } catch (InvalidKeyException e) {
      // Good!
      return;
    }
  }

  public void testBasicPreKeyV3()
      throws InvalidKeyException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, NoSessionException {
    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();

    final SignalProtocolStore bobStore                 = new TestInMemorySignalProtocolStore();
          ECKeyPair    bobPreKeyPair            = Curve.generateKeyPair();
          ECKeyPair    bobSignedPreKeyPair      = Curve.generateKeyPair();
          byte[]       bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                                                                           bobSignedPreKeyPair.getPublicKey().getBytes());

    // round-trip the identity key to test string encoding
    final SignalProtocolAddress bobAddress = new SignalProtocolAddress(new ECPublicKey(bobStore.getIdentityKeyPair().getPublicKey().toString()), DeviceId.random());
    final SignalProtocolAddress aliceAddress = new SignalProtocolAddress(aliceStore.getIdentityKeyPair().getPublicKey(), DeviceId.random());

    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, bobAddress);

    PreKeyBundle bobPreKey = new PreKeyBundle(31337, bobPreKeyPair.getPublicKey(),
                                              22, bobSignedPreKeyPair.getPublicKey(),
                                              bobSignedPreKeySignature,
                                              bobStore.getIdentityKeyPair().getPublicKey());

    aliceSessionBuilder.process(bobPreKey);

    assertTrue(aliceStore.containsSession(bobAddress));
    assertTrue(aliceStore.loadSession(bobAddress).getSessionState().getSessionVersion() == 3);

    final String            originalMessage    = "L'homme est condamné à être libre";
          SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, bobAddress);
          CiphertextMessage outgoingMessage    = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());
    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
    bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

    SessionCipher bobSessionCipher = new SessionCipher(bobStore, aliceAddress);
    byte[] plaintext = bobSessionCipher.decrypt(incomingMessage, new DecryptionCallback() {
      @Override
      public void handlePlaintext(byte[] plaintext) {
        assertTrue(originalMessage.equals(new String(plaintext)));
        assertFalse(bobStore.containsSession(aliceAddress));
      }
    });

    assertTrue(bobStore.containsSession(aliceAddress));
    assertTrue(bobStore.loadSession(aliceAddress).getSessionState().getSessionVersion() == 3);
    assertTrue(bobStore.loadSession(aliceAddress).getSessionState().getAliceBaseKey() != null);
    assertTrue(originalMessage.equals(new String(plaintext)));

    CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
    assertTrue(bobOutgoingMessage.getType() == CiphertextMessage.WHISPER_TYPE);

    byte[] alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
    assertTrue(new String(alicePlaintext).equals(originalMessage));

    runInteraction(aliceStore, bobStore, aliceAddress, bobAddress);

    // From what I can tell, the below was testing that we can successfully handle Alice's identity
    // key changing. That's no longer possible since the address and the identity key are tied
    // together.

//    aliceStore          = new TestInMemorySignalProtocolStore();
//    aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
//    aliceSessionCipher  = new SessionCipher(aliceStore, BOB_ADDRESS);
//
//    bobPreKeyPair            = Curve.generateKeyPair();
//    bobSignedPreKeyPair      = Curve.generateKeyPair();
//    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(), bobSignedPreKeyPair.getPublicKey().serialize());
//    bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(),
//            1, 31338, bobPreKeyPair.getPublicKey(),
//            23, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
//            bobStore.getIdentityKeyPair().getPublicKey());
//
//    bobStore.storePreKey(31338, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
//    bobStore.storeSignedPreKey(23, new SignedPreKeyRecord(23, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));
//    aliceSessionBuilder.process(bobPreKey);
//
//    outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());
//
//    try {
//      plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(outgoingMessage.serialize()));
//      throw new AssertionError("shouldn't be trusted!");
//    } catch (UntrustedIdentityException uie) {
//      bobStore.saveIdentity(ALICE_ADDRESS, new PreKeySignalMessage(outgoingMessage.serialize()).getIdentityKey());
//    }
//
//    plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(outgoingMessage.serialize()));
//    assertTrue(new String(plaintext).equals(originalMessage));
//
//    bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
//            31337, Curve.generateKeyPair().getPublicKey(),
//            23, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
//            aliceStore.getIdentityKeyPair().getPublicKey());
//
//    try {
//      aliceSessionBuilder.process(bobPreKey);
//      throw new AssertionError("shoulnd't be trusted!");
//    } catch (UntrustedIdentityException uie) {
//      // good
//    }
  }

  public void testBadSignedPreKeySignature() throws InvalidKeyException {
    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
    IdentityKeyStore bobIdentityKeyStore = new TestInMemoryIdentityKeyStore();

    ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
    ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
    byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobIdentityKeyStore.getIdentityKeyPair().getPrivateKey(),
                                                                  bobSignedPreKeyPair.getPublicKey().getBytes());

    final SignalProtocolAddress bobAddress = new SignalProtocolAddress(bobIdentityKeyStore.getIdentityKeyPair().getPublicKey(), DeviceId.random());

    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, bobAddress);

    for (int i=0;i<bobSignedPreKeySignature.length * 8;i++) {
      byte[] modifiedSignature = new byte[bobSignedPreKeySignature.length];
      System.arraycopy(bobSignedPreKeySignature, 0, modifiedSignature, 0, modifiedSignature.length);

      modifiedSignature[i/8] ^= (0x01 << (i % 8));

      PreKeyBundle bobPreKey = new PreKeyBundle(31337, bobPreKeyPair.getPublicKey(),
                                                22, bobSignedPreKeyPair.getPublicKey(), modifiedSignature,
                                                bobIdentityKeyStore.getIdentityKeyPair().getPublicKey());

      try {
        aliceSessionBuilder.process(bobPreKey);
        throw new AssertionError("Accepted modified device key signature!");
      } catch (InvalidKeyException ike) {
        // good
      }
    }

    PreKeyBundle bobPreKey = new PreKeyBundle(31337, bobPreKeyPair.getPublicKey(),
                                              22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                              bobIdentityKeyStore.getIdentityKeyPair().getPublicKey());

    aliceSessionBuilder.process(bobPreKey);
  }

  public void testRepeatBundleMessageV2() throws InvalidKeyException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, NoSessionException {
    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();

    SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

    ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
    ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
    byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                                                                  bobSignedPreKeyPair.getPublicKey().getBytes());

    final SignalProtocolAddress bobAddress = new SignalProtocolAddress(bobStore.getIdentityKeyPair().getPublicKey(), DeviceId.random());
    final SignalProtocolAddress aliceAddress = new SignalProtocolAddress(aliceStore.getIdentityKeyPair().getPublicKey(), DeviceId.random());

    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, bobAddress);
    PreKeyBundle bobPreKey = new PreKeyBundle(31337, bobPreKeyPair.getPublicKey(),
                                              0, null, null,
                                              bobStore.getIdentityKeyPair().getPublicKey());

    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
    bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

    try {
      aliceSessionBuilder.process(bobPreKey);
      throw new AssertionError("Should fail with missing signed prekey!");
    } catch (InvalidKeyException e) {
      // Good!
      return;
    }
  }

  public void testRepeatBundleMessageV3() throws InvalidKeyException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, NoSessionException {
    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();

    SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

    ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
    ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
    byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                                                                  bobSignedPreKeyPair.getPublicKey().getBytes());

    final SignalProtocolAddress bobAddress = new SignalProtocolAddress(bobStore.getIdentityKeyPair().getPublicKey(), DeviceId.random());
    final SignalProtocolAddress aliceAddress = new SignalProtocolAddress(aliceStore.getIdentityKeyPair().getPublicKey(), DeviceId.random());

    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, bobAddress);

    PreKeyBundle bobPreKey = new PreKeyBundle(31337, bobPreKeyPair.getPublicKey(),
                                              22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                              bobStore.getIdentityKeyPair().getPublicKey());

    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
    bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

    aliceSessionBuilder.process(bobPreKey);

    String            originalMessage    = "L'homme est condamné à être libre";
    SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, bobAddress);
    CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());
    CiphertextMessage outgoingMessageTwo = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);
    assertTrue(outgoingMessageTwo.getType() == CiphertextMessage.PREKEY_TYPE);

    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessageOne.serialize());

    SessionCipher bobSessionCipher = new SessionCipher(bobStore, aliceAddress);

    byte[]        plaintext        = bobSessionCipher.decrypt(incomingMessage);
    assertTrue(originalMessage.equals(new String(plaintext)));

    CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

    byte[] alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
    assertTrue(originalMessage.equals(new String(alicePlaintext)));

    // The test

    PreKeySignalMessage incomingMessageTwo = new PreKeySignalMessage(outgoingMessageTwo.serialize());

    plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(incomingMessageTwo.serialize()));
    assertTrue(originalMessage.equals(new String(plaintext)));

    bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
    alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
    assertTrue(originalMessage.equals(new String(alicePlaintext)));

  }

  public void testBadMessageBundle() throws InvalidKeyException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, LegacyMessageException, InvalidKeyIdException {
    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();

    SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

    ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
    ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
    byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                                                                  bobSignedPreKeyPair.getPublicKey().getBytes());

    final SignalProtocolAddress bobAddress = new SignalProtocolAddress(bobStore.getIdentityKeyPair().getPublicKey(), DeviceId.random());
    final SignalProtocolAddress aliceAddress = new SignalProtocolAddress(aliceStore.getIdentityKeyPair().getPublicKey(), DeviceId.random());

    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, bobAddress);
    PreKeyBundle bobPreKey = new PreKeyBundle(31337, bobPreKeyPair.getPublicKey(),
                                              22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                              bobStore.getIdentityKeyPair().getPublicKey());

    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
    bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

    aliceSessionBuilder.process(bobPreKey);

    String            originalMessage    = "L'homme est condamné à être libre";
    SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, bobAddress);
    CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);

    byte[] goodMessage = outgoingMessageOne.serialize();
    byte[] badMessage  = new byte[goodMessage.length];
    System.arraycopy(goodMessage, 0, badMessage, 0, badMessage.length);

    badMessage[badMessage.length-10] ^= 0x01;

    PreKeySignalMessage incomingMessage  = new PreKeySignalMessage(badMessage);
    SessionCipher        bobSessionCipher = new SessionCipher(bobStore, aliceAddress);

    byte[] plaintext = new byte[0];

    try {
      plaintext = bobSessionCipher.decrypt(incomingMessage);
      throw new AssertionError("Decrypt should have failed!");
    } catch (InvalidMessageException e) {
      // good.
    }

    assertTrue(bobStore.containsPreKey(31337));

    plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(goodMessage));

    assertTrue(originalMessage.equals(new String(plaintext)));
    assertTrue(!bobStore.containsPreKey(31337));
  }

  public void testOptionalOneTimePreKey() throws Exception {
    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();

    SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

    ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
    ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
    byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                                                                  bobSignedPreKeyPair.getPublicKey().getBytes());

    final SignalProtocolAddress bobAddress = new SignalProtocolAddress(bobStore.getIdentityKeyPair().getPublicKey(), DeviceId.random());
    final SignalProtocolAddress aliceAddress = new SignalProtocolAddress(aliceStore.getIdentityKeyPair().getPublicKey(), DeviceId.random());

    PreKeyBundle bobPreKey = new PreKeyBundle(0, null,
                                              22, bobSignedPreKeyPair.getPublicKey(),
                                              bobSignedPreKeySignature,
                                              bobStore.getIdentityKeyPair().getPublicKey());

    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, bobAddress);
    aliceSessionBuilder.process(bobPreKey);

    assertTrue(aliceStore.containsSession(bobAddress));
    assertTrue(aliceStore.loadSession(bobAddress).getSessionState().getSessionVersion() == 3);

    String            originalMessage    = "L'homme est condamné à être libre";
    SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, bobAddress);
    CiphertextMessage outgoingMessage    = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());
    assertTrue(!incomingMessage.getPreKeyId().isPresent());

    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
    bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

    SessionCipher bobSessionCipher = new SessionCipher(bobStore, aliceAddress);
    byte[]        plaintext        = bobSessionCipher.decrypt(incomingMessage);

    assertTrue(bobStore.containsSession(aliceAddress));
    assertTrue(bobStore.loadSession(aliceAddress).getSessionState().getSessionVersion() == 3);
    assertTrue(bobStore.loadSession(aliceAddress).getSessionState().getAliceBaseKey() != null);
    assertTrue(originalMessage.equals(new String(plaintext)));
  }


  private void runInteraction(SignalProtocolStore aliceStore, SignalProtocolStore bobStore, SignalProtocolAddress aliceAddress, SignalProtocolAddress bobAddress)
      throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, NoSessionException
  {
    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, bobAddress);
    SessionCipher bobSessionCipher   = new SessionCipher(bobStore, aliceAddress);

    String originalMessage = "smert ze smert";
    CiphertextMessage aliceMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(aliceMessage.getType() == CiphertextMessage.WHISPER_TYPE);

    byte[] plaintext = bobSessionCipher.decrypt(new SignalMessage(aliceMessage.serialize()));
    assertTrue(new String(plaintext).equals(originalMessage));

    CiphertextMessage bobMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(bobMessage.getType() == CiphertextMessage.WHISPER_TYPE);

    plaintext = aliceSessionCipher.decrypt(new SignalMessage(bobMessage.serialize()));
    assertTrue(new String(plaintext).equals(originalMessage));

    for (int i=0;i<10;i++) {
      String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                               "We mean that man first of all exists, encounters himself, " +
                               "surges up in the world--and defines himself aftward. " + i);
      CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

      byte[] loopingPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
      assertTrue(new String(loopingPlaintext).equals(loopingMessage));
    }

    for (int i=0;i<10;i++) {
      String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                               "We mean that man first of all exists, encounters himself, " +
                               "surges up in the world--and defines himself aftward. " + i);
      CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

      byte[] loopingPlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
      assertTrue(new String(loopingPlaintext).equals(loopingMessage));
    }

    Set<Pair<String, CiphertextMessage>> aliceOutOfOrderMessages = new HashSet<>();

    for (int i=0;i<10;i++) {
      String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                               "We mean that man first of all exists, encounters himself, " +
                               "surges up in the world--and defines himself aftward. " + i);
      CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

      aliceOutOfOrderMessages.add(new Pair<>(loopingMessage, aliceLoopingMessage));
    }

    for (int i=0;i<10;i++) {
      String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                               "We mean that man first of all exists, encounters himself, " +
                               "surges up in the world--and defines himself aftward. " + i);
      CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

      byte[] loopingPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
      assertTrue(new String(loopingPlaintext).equals(loopingMessage));
    }

    for (int i=0;i<10;i++) {
      String loopingMessage = ("You can only desire based on what you know: " + i);
      CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

      byte[] loopingPlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
      assertTrue(new String(loopingPlaintext).equals(loopingMessage));
    }

    for (Pair<String, CiphertextMessage> aliceOutOfOrderMessage : aliceOutOfOrderMessages) {
      byte[] outOfOrderPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceOutOfOrderMessage.second().serialize()));
      assertTrue(new String(outOfOrderPlaintext).equals(aliceOutOfOrderMessage.first()));
    }
  }


}
