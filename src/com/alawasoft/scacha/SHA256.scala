package com.alawasoft.scacha

object SHA256 {

  private val K: Array[Int] = Array(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  )

  private inline def rotr(x: Int, n: Int): Int = (x >>> n) | (x << (32 - n))
  private inline def ch(x: Int, y: Int, z: Int): Int = (x & y) ^ (~x & z)
  private inline def maj(x: Int, y: Int, z: Int): Int = (x & y) ^ (x & z) ^ (y & z)
  private inline def sigma0(x: Int): Int = rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
  private inline def sigma1(x: Int): Int = rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
  private inline def gamma0(x: Int): Int = rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)
  private inline def gamma1(x: Int): Int = rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10)

  def hash(data: Array[Byte]): Array[Byte] = {
    val msgLen = data.length.toLong * 8
    // Padding: append 1 bit, then zeros, then 64-bit length
    val padLen = {
      val mod = (data.length + 1) % 64
      if (mod <= 56) 56 - mod else 120 - mod
    }
    val padded = new Array[Byte](data.length + 1 + padLen + 8)
    System.arraycopy(data, 0, padded, 0, data.length)
    padded(data.length) = 0x80.toByte
    // Write length as big-endian 64-bit
    var i = 0
    while (i < 8) {
      padded(padded.length - 8 + i) = ((msgLen >>> (56 - i * 8)) & 0xff).toByte
      i += 1
    }

    var h0 = 0x6a09e667
    var h1 = 0xbb67ae85
    var h2 = 0x3c6ef372
    var h3 = 0xa54ff53a
    var h4 = 0x510e527f
    var h5 = 0x9b05688c
    var h6 = 0x1f83d9ab
    var h7 = 0x5be0cd19

    val w = new Array[Int](64)
    var block = 0
    while (block < padded.length) {
      i = 0
      while (i < 16) {
        val off = block + i * 4
        w(i) = ((padded(off) & 0xff) << 24) |
          ((padded(off + 1) & 0xff) << 16) |
          ((padded(off + 2) & 0xff) << 8) |
          (padded(off + 3) & 0xff)
        i += 1
      }
      while (i < 64) {
        w(i) = gamma1(w(i - 2)) + w(i - 7) + gamma0(w(i - 15)) + w(i - 16)
        i += 1
      }

      var a = h0; var b = h1; var c = h2; var d = h3
      var e = h4; var f = h5; var g = h6; var h = h7

      i = 0
      while (i < 64) {
        val t1 = h + sigma1(e) + ch(e, f, g) + K(i) + w(i)
        val t2 = sigma0(a) + maj(a, b, c)
        h = g; g = f; f = e; e = d + t1
        d = c; c = b; b = a; a = t1 + t2
        i += 1
      }

      h0 += a; h1 += b; h2 += c; h3 += d
      h4 += e; h5 += f; h6 += g; h7 += h
      block += 64
    }

    val result = new Array[Byte](32)
    intToBE(h0, result, 0)
    intToBE(h1, result, 4)
    intToBE(h2, result, 8)
    intToBE(h3, result, 12)
    intToBE(h4, result, 16)
    intToBE(h5, result, 20)
    intToBE(h6, result, 24)
    intToBE(h7, result, 28)
    result
  }

  private def intToBE(v: Int, bs: Array[Byte], off: Int): Unit = {
    bs(off) = ((v >>> 24) & 0xff).toByte
    bs(off + 1) = ((v >>> 16) & 0xff).toByte
    bs(off + 2) = ((v >>> 8) & 0xff).toByte
    bs(off + 3) = (v & 0xff).toByte
  }
}
