/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.state;


import com.google.protobuf.ByteString;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.kdf.HKDF;
import org.whispersystems.libsignal.logging.Log;
import org.whispersystems.libsignal.ratchet.ChainKey;
import org.whispersystems.libsignal.ratchet.MessageKeys;
import org.whispersystems.libsignal.ratchet.RootKey;
import org.whispersystems.libsignal.state.StorageProtos.SessionStructure.Chain;
import org.whispersystems.libsignal.state.StorageProtos.SessionStructure.PendingKeyExchange;
import org.whispersystems.libsignal.state.StorageProtos.SessionStructure.PendingPreKey;
import org.whispersystems.libsignal.util.Pair;
import org.whispersystems.libsignal.util.guava.Optional;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static org.whispersystems.libsignal.state.StorageProtos.SessionStructure;

public class SessionState {

  private static final int MAX_MESSAGE_KEYS = 2000;

  private SessionStructure sessionStructure;

  public SessionState() {
    this.sessionStructure = SessionStructure.newBuilder().build();
  }

  public SessionState(SessionStructure sessionStructure) {
    this.sessionStructure = sessionStructure;
  }

  public SessionState(SessionState copy) {
    this.sessionStructure = copy.sessionStructure.toBuilder().build();
  }

  public SessionStructure getStructure() {
    return sessionStructure;
  }

  public byte[] getAliceBaseKey() {
    return this.sessionStructure.getAliceBaseKey().toByteArray();
  }

  public void setAliceBaseKey(byte[] aliceBaseKey) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setAliceBaseKey(ByteString.copyFrom(aliceBaseKey))
                                                 .build();
  }

  public void setSessionVersion(int version) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setSessionVersion(version)
                                                 .build();
  }

  public int getSessionVersion() {
    int sessionVersion = this.sessionStructure.getSessionVersion();

    if (sessionVersion == 0) return 2;
    else                     return sessionVersion;
  }

  public void setRemoteIdentityKey(ECPublicKey identityKey) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setRemoteIdentityPublic(ByteString.copyFrom(identityKey.getBytes()))
                                                 .build();
  }

  public void setLocalIdentityKey(ECPublicKey identityKey) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setLocalIdentityPublic(ByteString.copyFrom(identityKey.getBytes()))
                                                 .build();
  }

  public ECPublicKey getRemoteIdentityKey() {
    try {
      if (!this.sessionStructure.hasRemoteIdentityPublic()) {
        return null;
      }

      return new ECPublicKey(this.sessionStructure.getRemoteIdentityPublic().toByteArray());
    } catch (InvalidKeyException e) {
      Log.w("SessionRecordV2", e);
      return null;
    }
  }

  public ECPublicKey getLocalIdentityKey() {
    try {
      return new ECPublicKey(this.sessionStructure.getLocalIdentityPublic().toByteArray());
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public int getPreviousCounter() {
    return sessionStructure.getPreviousCounter();
  }

  public void setPreviousCounter(int previousCounter) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setPreviousCounter(previousCounter)
                                                 .build();
  }

  public RootKey getRootKey() {
    return new RootKey(HKDF.createFor(getSessionVersion()),
                       this.sessionStructure.getRootKey().toByteArray());
  }

  public void setRootKey(RootKey rootKey) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setRootKey(ByteString.copyFrom(rootKey.getKeyBytes()))
                                                 .build();
  }

  public ECPublicKey getSenderRatchetKey() {
    try {
      return new ECPublicKey(sessionStructure.getSenderChain().getSenderRatchetKey().toByteArray());
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public ECKeyPair getSenderRatchetKeyPair() {
    ECPublicKey  publicKey  = getSenderRatchetKey();
    ECPrivateKey privateKey = new ECPrivateKey(sessionStructure.getSenderChain()
                                                                       .getSenderRatchetKeyPrivate()
                                                                       .toByteArray());

    return new ECKeyPair(publicKey, privateKey);
  }

  public boolean hasReceiverChain(ECPublicKey senderEphemeral) {
    return getReceiverChain(senderEphemeral) != null;
  }

  public boolean hasSenderChain() {
    return sessionStructure.hasSenderChain();
  }

  private Pair<Chain,Integer> getReceiverChain(ECPublicKey senderEphemeral) {
    List<Chain> receiverChains = sessionStructure.getReceiverChainsList();
    int         index          = 0;

    for (Chain receiverChain : receiverChains) {
      try {
        ECPublicKey chainSenderRatchetKey = new ECPublicKey(receiverChain.getSenderRatchetKey().toByteArray());

        if (chainSenderRatchetKey.equals(senderEphemeral)) {
          return new Pair<>(receiverChain,index);
        }
      } catch (InvalidKeyException e) {
        Log.w("SessionRecordV2", e);
      }

      index++;
    }

    return null;
  }

  public ChainKey getReceiverChainKey(ECPublicKey senderEphemeral) {
    Pair<Chain,Integer> receiverChainAndIndex = getReceiverChain(senderEphemeral);
    Chain               receiverChain         = receiverChainAndIndex.first();

    if (receiverChain == null) {
      return null;
    } else {
      return new ChainKey(HKDF.createFor(getSessionVersion()),
                          receiverChain.getChainKey().getKey().toByteArray(),
                          receiverChain.getChainKey().getIndex());
    }
  }

  public void addReceiverChain(ECPublicKey senderRatchetKey, ChainKey chainKey) {
    Chain.ChainKey chainKeyStructure = Chain.ChainKey.newBuilder()
                                                     .setKey(ByteString.copyFrom(chainKey.getKey()))
                                                     .setIndex(chainKey.getIndex())
                                                     .build();

    Chain chain = Chain.newBuilder()
                       .setChainKey(chainKeyStructure)
                       .setSenderRatchetKey(ByteString.copyFrom(senderRatchetKey.getBytes()))
                       .build();

    this.sessionStructure = this.sessionStructure.toBuilder().addReceiverChains(chain).build();

    if (this.sessionStructure.getReceiverChainsList().size() > 5) {
      this.sessionStructure = this.sessionStructure.toBuilder()
                                                   .removeReceiverChains(0)
                                                   .build();
    }
  }

  public void setSenderChain(ECKeyPair senderRatchetKeyPair, ChainKey chainKey) {
    Chain.ChainKey chainKeyStructure = Chain.ChainKey.newBuilder()
                                                     .setKey(ByteString.copyFrom(chainKey.getKey()))
                                                     .setIndex(chainKey.getIndex())
                                                     .build();

    Chain senderChain = Chain.newBuilder()
                             .setSenderRatchetKey(ByteString.copyFrom(senderRatchetKeyPair.getPublicKey().getBytes()))
                             .setSenderRatchetKeyPrivate(ByteString.copyFrom(senderRatchetKeyPair.getPrivateKey().getBytes()))
                             .setChainKey(chainKeyStructure)
                             .build();

    this.sessionStructure = this.sessionStructure.toBuilder().setSenderChain(senderChain).build();
  }

  public ChainKey getSenderChainKey() {
    Chain.ChainKey chainKeyStructure = sessionStructure.getSenderChain().getChainKey();
    return new ChainKey(HKDF.createFor(getSessionVersion()),
                        chainKeyStructure.getKey().toByteArray(), chainKeyStructure.getIndex());
  }


  public void setSenderChainKey(ChainKey nextChainKey) {
    Chain.ChainKey chainKey = Chain.ChainKey.newBuilder()
                                            .setKey(ByteString.copyFrom(nextChainKey.getKey()))
                                            .setIndex(nextChainKey.getIndex())
                                            .build();

    Chain chain = sessionStructure.getSenderChain().toBuilder()
                                  .setChainKey(chainKey).build();

    this.sessionStructure = this.sessionStructure.toBuilder().setSenderChain(chain).build();
  }

  public boolean hasMessageKeys(ECPublicKey senderEphemeral, int counter) {
    Pair<Chain,Integer> chainAndIndex = getReceiverChain(senderEphemeral);
    Chain               chain         = chainAndIndex.first();

    if (chain == null) {
      return false;
    }

    List<Chain.MessageKey> messageKeyList = chain.getMessageKeysList();

    for (Chain.MessageKey messageKey : messageKeyList) {
      if (messageKey.getIndex() == counter) {
        return true;
      }
    }

    return false;
  }

  public MessageKeys removeMessageKeys(ECPublicKey senderEphemeral, int counter) {
    Pair<Chain,Integer> chainAndIndex = getReceiverChain(senderEphemeral);
    Chain               chain         = chainAndIndex.first();

    if (chain == null) {
      return null;
    }

    List<Chain.MessageKey>     messageKeyList     = new LinkedList<>(chain.getMessageKeysList());
    Iterator<Chain.MessageKey> messageKeyIterator = messageKeyList.iterator();
    MessageKeys                result             = null;

    while (messageKeyIterator.hasNext()) {
      Chain.MessageKey messageKey = messageKeyIterator.next();

      if (messageKey.getIndex() == counter) {
        result = new MessageKeys(new SecretKeySpec(messageKey.getCipherKey().toByteArray(), "AES"),
                                 new SecretKeySpec(messageKey.getMacKey().toByteArray(), "HmacSHA256"),
                                 new IvParameterSpec(messageKey.getIv().toByteArray()),
                                 messageKey.getIndex());

        messageKeyIterator.remove();
        break;
      }
    }

    Chain updatedChain = chain.toBuilder().clearMessageKeys()
                              .addAllMessageKeys(messageKeyList)
                              .build();

    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setReceiverChains(chainAndIndex.second(), updatedChain)
                                                 .build();

    return result;
  }

  public void setMessageKeys(ECPublicKey senderEphemeral, MessageKeys messageKeys) {
    Pair<Chain,Integer> chainAndIndex       = getReceiverChain(senderEphemeral);
    Chain               chain               = chainAndIndex.first();
    Chain.MessageKey    messageKeyStructure = Chain.MessageKey.newBuilder()
                                                              .setCipherKey(ByteString.copyFrom(messageKeys.getCipherKey().getEncoded()))
                                                              .setMacKey(ByteString.copyFrom(messageKeys.getMacKey().getEncoded()))
                                                              .setIndex(messageKeys.getCounter())
                                                              .setIv(ByteString.copyFrom(messageKeys.getIv().getIV()))
                                                              .build();

    Chain.Builder updatedChain = chain.toBuilder().addMessageKeys(messageKeyStructure);

    if (updatedChain.getMessageKeysCount() > MAX_MESSAGE_KEYS) {
      updatedChain.removeMessageKeys(0);
    }

    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setReceiverChains(chainAndIndex.second(),
                                                                    updatedChain.build())
                                                 .build();
  }

  public void setReceiverChainKey(ECPublicKey senderEphemeral, ChainKey chainKey) {
    Pair<Chain,Integer> chainAndIndex = getReceiverChain(senderEphemeral);
    Chain               chain         = chainAndIndex.first();

    Chain.ChainKey chainKeyStructure = Chain.ChainKey.newBuilder()
                                                     .setKey(ByteString.copyFrom(chainKey.getKey()))
                                                     .setIndex(chainKey.getIndex())
                                                     .build();

    Chain updatedChain = chain.toBuilder().setChainKey(chainKeyStructure).build();

    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setReceiverChains(chainAndIndex.second(), updatedChain)
                                                 .build();
  }

  public void setPendingKeyExchange(int sequence,
                                    ECKeyPair ourBaseKey,
                                    ECKeyPair ourRatchetKey,
                                    ECKeyPair ourIdentityKey)
  {
    PendingKeyExchange structure =
        PendingKeyExchange.newBuilder()
                          .setSequence(sequence)
                          .setLocalBaseKey(ByteString.copyFrom(ourBaseKey.getPublicKey().getBytes()))
                          .setLocalBaseKeyPrivate(ByteString.copyFrom(ourBaseKey.getPrivateKey().getBytes()))
                          .setLocalRatchetKey(ByteString.copyFrom(ourRatchetKey.getPublicKey().getBytes()))
                          .setLocalRatchetKeyPrivate(ByteString.copyFrom(ourRatchetKey.getPrivateKey().getBytes()))
                          .setLocalIdentityKey(ByteString.copyFrom(ourIdentityKey.getPublicKey().getBytes()))
                          .setLocalIdentityKeyPrivate(ByteString.copyFrom(ourIdentityKey.getPrivateKey().getBytes()))
                          .build();

    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setPendingKeyExchange(structure)
                                                 .build();
  }

  public int getPendingKeyExchangeSequence() {
    return sessionStructure.getPendingKeyExchange().getSequence();
  }

  public ECKeyPair getPendingKeyExchangeBaseKey() throws InvalidKeyException {
    ECPublicKey publicKey   = new ECPublicKey(sessionStructure.getPendingKeyExchange()
                                                                .getLocalBaseKey().toByteArray());

    ECPrivateKey privateKey = new ECPrivateKey(sessionStructure.getPendingKeyExchange()
                                                                       .getLocalBaseKeyPrivate()
                                                                       .toByteArray());

    return new ECKeyPair(publicKey, privateKey);
  }

  public ECKeyPair getPendingKeyExchangeRatchetKey() throws InvalidKeyException {
    ECPublicKey publicKey   = new ECPublicKey(sessionStructure.getPendingKeyExchange()
                                                                .getLocalRatchetKey().toByteArray());

    ECPrivateKey privateKey = new ECPrivateKey(sessionStructure.getPendingKeyExchange()
                                                                       .getLocalRatchetKeyPrivate()
                                                                       .toByteArray());

    return new ECKeyPair(publicKey, privateKey);
  }

  public ECKeyPair getPendingKeyExchangeIdentityKey() throws InvalidKeyException {
    ECPublicKey publicKey = new ECPublicKey(sessionStructure.getPendingKeyExchange()
                                                            .getLocalIdentityKey().toByteArray());

    ECPrivateKey privateKey = new ECPrivateKey(sessionStructure.getPendingKeyExchange()
                                                                       .getLocalIdentityKeyPrivate()
                                                                       .toByteArray());

    return new ECKeyPair(publicKey, privateKey);
  }

  public boolean hasPendingKeyExchange() {
    return sessionStructure.hasPendingKeyExchange();
  }

  public void setUnacknowledgedPreKeyMessage(Optional<Integer> preKeyId, int signedPreKeyId, ECPublicKey baseKey) {
    PendingPreKey.Builder pending = PendingPreKey.newBuilder()
                                                 .setSignedPreKeyId(signedPreKeyId)
                                                 .setBaseKey(ByteString.copyFrom(baseKey.getBytes()));

    if (preKeyId.isPresent()) {
      pending.setPreKeyId(preKeyId.get());
    }

    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setPendingPreKey(pending.build())
                                                 .build();
  }

  public boolean hasUnacknowledgedPreKeyMessage() {
    return this.sessionStructure.hasPendingPreKey();
  }

  public UnacknowledgedPreKeyMessageItems getUnacknowledgedPreKeyMessageItems() {
    try {
      Optional<Integer> preKeyId;

      if (sessionStructure.getPendingPreKey().hasPreKeyId()) {
        preKeyId = Optional.of(sessionStructure.getPendingPreKey().getPreKeyId());
      } else {
        preKeyId = Optional.absent();
      }

      return
          new UnacknowledgedPreKeyMessageItems(preKeyId,
                                               sessionStructure.getPendingPreKey().getSignedPreKeyId(),
                                               new ECPublicKey(sessionStructure.getPendingPreKey()
                                                                                 .getBaseKey()
                                                                                 .toByteArray()));
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public void clearUnacknowledgedPreKeyMessage() {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .clearPendingPreKey()
                                                 .build();
  }

  public byte[] serialize() {
    return sessionStructure.toByteArray();
  }

  public static class UnacknowledgedPreKeyMessageItems {
    private final Optional<Integer> preKeyId;
    private final int               signedPreKeyId;
    private final ECPublicKey       baseKey;

    public UnacknowledgedPreKeyMessageItems(Optional<Integer> preKeyId,
                                            int signedPreKeyId,
                                            ECPublicKey baseKey)
    {
      this.preKeyId       = preKeyId;
      this.signedPreKeyId = signedPreKeyId;
      this.baseKey        = baseKey;
    }


    public Optional<Integer> getPreKeyId() {
      return preKeyId;
    }

    public int getSignedPreKeyId() {
      return signedPreKeyId;
    }

    public ECPublicKey getBaseKey() {
      return baseKey;
    }
  }
}
