/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

public class InvalidAddressException extends Exception {

  public InvalidAddressException() {}

  public InvalidAddressException(String detailMessage) {
    super(detailMessage);
  }

  public InvalidAddressException(Throwable throwable) {
    super(throwable);
  }

  public InvalidAddressException(String detailMessage, Throwable throwable) {
    super(detailMessage, throwable);
  }
}
