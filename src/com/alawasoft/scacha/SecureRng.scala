package com.alawasoft.scacha

import java.nio.channels.FileChannel
import java.nio.ByteBuffer
import java.nio.file.{Path, StandardOpenOption}

object SecureRng {

  def nextBytes(buf: Array[Byte]): Unit = {
    val ch = FileChannel.open(Path.of("/dev/urandom"), StandardOpenOption.READ)
    try {
      val bb = ByteBuffer.wrap(buf)
      while (bb.hasRemaining) {
        ch.read(bb)
      }
    } finally {
      ch.close()
    }
  }
}
