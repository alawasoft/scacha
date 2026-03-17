package com.alawasoft.scacha

object KeyDerivation {

  def fromHex(hex: String): Either[String, Array[Byte]] = {
    if (hex.length != 64) {
      Left(s"Hex key must be 64 characters (32 bytes), got ${hex.length}")
    } else if (!hex.forall(c => "0123456789abcdefABCDEF".contains(c))) {
      Left("Hex key contains invalid characters")
    } else {
      val bytes = new Array[Byte](32)
      var i = 0
      while (i < 32) {
        bytes(i) = Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16).toByte
        i += 1
      }
      Right(bytes)
    }
  }

  def fromPassphrase(passphrase: String, salt: Array[Byte]): Array[Byte] = {
    val input = salt ++ passphrase.getBytes("UTF-8")
    SHA256.hash(input)
  }
}
