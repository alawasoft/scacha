package com.alawasoft.scacha

object ChaCha20 {

  private val Constants: Array[Int] = Array(
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
  )

  private inline def rotl32(v: Int, n: Int): Int =
    (v << n) | (v >>> (32 - n))

  private def littleEndianToInt(bs: Array[Byte], off: Int): Int =
    (bs(off) & 0xff) |
      ((bs(off + 1) & 0xff) << 8) |
      ((bs(off + 2) & 0xff) << 16) |
      ((bs(off + 3) & 0xff) << 24)

  private def intToLittleEndian(n: Int, bs: Array[Byte], off: Int): Unit = {
    bs(off) = (n & 0xff).toByte
    bs(off + 1) = ((n >>> 8) & 0xff).toByte
    bs(off + 2) = ((n >>> 16) & 0xff).toByte
    bs(off + 3) = ((n >>> 24) & 0xff).toByte
  }

  private def quarterRound(state: Array[Int], a: Int, b: Int, c: Int, d: Int): Unit = {
    state(a) += state(b); state(d) = rotl32(state(d) ^ state(a), 16)
    state(c) += state(d); state(b) = rotl32(state(b) ^ state(c), 12)
    state(a) += state(b); state(d) = rotl32(state(d) ^ state(a), 8)
    state(c) += state(d); state(b) = rotl32(state(b) ^ state(c), 7)
  }

  def chachaBlock(key: Array[Byte], counter: Int, nonce: Array[Byte]): Array[Byte] = {
    require(key.length == 32, s"Key must be 32 bytes, got ${key.length}")
    require(nonce.length == 12, s"Nonce must be 12 bytes, got ${nonce.length}")

    val state = new Array[Int](16)
    state(0) = Constants(0)
    state(1) = Constants(1)
    state(2) = Constants(2)
    state(3) = Constants(3)

    var i = 0
    while (i < 8) {
      state(4 + i) = littleEndianToInt(key, i * 4)
      i += 1
    }

    state(12) = counter
    state(13) = littleEndianToInt(nonce, 0)
    state(14) = littleEndianToInt(nonce, 4)
    state(15) = littleEndianToInt(nonce, 8)

    val working = state.clone()

    var round = 0
    while (round < 10) {
      // Column rounds
      quarterRound(working, 0, 4, 8, 12)
      quarterRound(working, 1, 5, 9, 13)
      quarterRound(working, 2, 6, 10, 14)
      quarterRound(working, 3, 7, 11, 15)
      // Diagonal rounds
      quarterRound(working, 0, 5, 10, 15)
      quarterRound(working, 1, 6, 11, 12)
      quarterRound(working, 2, 7, 8, 13)
      quarterRound(working, 3, 4, 9, 14)
      round += 1
    }

    val output = new Array[Byte](64)
    i = 0
    while (i < 16) {
      intToLittleEndian(working(i) + state(i), output, i * 4)
      i += 1
    }
    output
  }

  def xorStream(key: Array[Byte], nonce: Array[Byte], counter: Int, data: Array[Byte]): Array[Byte] = {
    val output = new Array[Byte](data.length)
    var blockCounter = counter
    var offset = 0

    while (offset < data.length) {
      val keyBlock = chachaBlock(key, blockCounter, nonce)
      val bytesInBlock = math.min(64, data.length - offset)
      var i = 0
      while (i < bytesInBlock) {
        output(offset + i) = (data(offset + i) ^ keyBlock(i)).toByte
        i += 1
      }
      offset += bytesInBlock
      blockCounter += 1
    }
    output
  }
}
