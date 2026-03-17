package com.alawasoft.scacha

import java.nio.ByteBuffer
import java.nio.channels.FileChannel

object ScachaFormat {

  val Magic: Array[Byte] = "SCACHA01".getBytes("US-ASCII")
  val HeaderSize: Int = 37

  val KeyModeRaw: Byte = 0x00
  val KeyModePassphrase: Byte = 0x01

  case class Header(
    keyMode: Byte,
    salt: Array[Byte],
    nonce: Array[Byte]
  )

  def writeHeader(channel: FileChannel, keyMode: Byte, salt: Array[Byte], nonce: Array[Byte]): Unit = {
    val buf = ByteBuffer.allocate(HeaderSize)
    buf.put(Magic)
    buf.put(keyMode)
    buf.put(salt)
    buf.put(nonce)
    buf.flip()
    channel.write(buf)
  }

  def readHeader(channel: FileChannel): Either[String, Header] = {
    val buf = ByteBuffer.allocate(HeaderSize)
    val bytesRead = channel.read(buf)
    if (bytesRead < HeaderSize) {
      Left("File too small to contain scacha header")
    } else {
      buf.flip()
      val magic = new Array[Byte](8)
      buf.get(magic)
      if (!magic.sameElements(Magic)) {
        Left("Invalid magic bytes — not a .scacha file")
      } else {
        val keyMode = buf.get()
        val salt = new Array[Byte](16)
        buf.get(salt)
        val nonce = new Array[Byte](12)
        buf.get(nonce)
        Right(Header(keyMode, salt, nonce))
      }
    }
  }
}
