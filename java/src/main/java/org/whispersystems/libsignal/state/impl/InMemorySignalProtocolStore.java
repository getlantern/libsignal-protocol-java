/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state.impl;

import org.whispersystems.libsignal.DeviceId;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import java.util.List;

public class InMemorySignalProtocolStore implements SignalProtocolStore {

  private final InMemoryPreKeyStore       preKeyStore       = new InMemoryPreKeyStore();
  private final InMemorySessionStore      sessionStore      = new InMemorySessionStore();
  private final InMemorySignedPreKeyStore signedPreKeyStore = new InMemorySignedPreKeyStore();

  private final InMemoryIdentityKeyStore  identityKeyStore;

  public InMemorySignalProtocolStore(ECKeyPair identityKeyPair) {
    this.identityKeyStore = new InMemoryIdentityKeyStore(identityKeyPair);
  }

  @Override
  public ECKeyPair getIdentityKeyPair() {
    return identityKeyStore.getIdentityKeyPair();
  }

  @Override
  public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
    return preKeyStore.loadPreKey(preKeyId);
  }

  @Override
  public void storePreKey(int preKeyId, PreKeyRecord record) {
    preKeyStore.storePreKey(preKeyId, record);
  }

  @Override
  public boolean containsPreKey(int preKeyId) {
    return preKeyStore.containsPreKey(preKeyId);
  }

  @Override
  public void removePreKey(int preKeyId) {
    preKeyStore.removePreKey(preKeyId);
  }

  @Override
  public SessionRecord loadSession(SignalProtocolAddress address) {
    return sessionStore.loadSession(address);
  }

  @Override
  public List<DeviceId> getSubDeviceSessions(String name) {
    return sessionStore.getSubDeviceSessions(name);
  }

  @Override
  public void storeSession(SignalProtocolAddress address, SessionRecord record) {
    sessionStore.storeSession(address, record);
  }

  @Override
  public boolean containsSession(SignalProtocolAddress address) {
    return sessionStore.containsSession(address);
  }

  @Override
  public void deleteSession(SignalProtocolAddress address) {
    sessionStore.deleteSession(address);
  }

  @Override
  public void deleteAllSessions(String name) {
    sessionStore.deleteAllSessions(name);
  }

  @Override
  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
    return signedPreKeyStore.loadSignedPreKey(signedPreKeyId);
  }

  @Override
  public List<SignedPreKeyRecord> loadSignedPreKeys() {
    return signedPreKeyStore.loadSignedPreKeys();
  }

  @Override
  public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
    signedPreKeyStore.storeSignedPreKey(signedPreKeyId, record);
  }

  @Override
  public boolean containsSignedPreKey(int signedPreKeyId) {
    return signedPreKeyStore.containsSignedPreKey(signedPreKeyId);
  }

  @Override
  public void removeSignedPreKey(int signedPreKeyId) {
    signedPreKeyStore.removeSignedPreKey(signedPreKeyId);
  }
}
