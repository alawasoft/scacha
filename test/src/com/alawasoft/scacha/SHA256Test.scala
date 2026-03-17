package com.alawasoft.scacha

import munit.FunSuite

class SHA256Test extends FunSuite {

  private def toHex(bytes: Array[Byte]): String =
    bytes.map(b => f"${b & 0xff}%02x").mkString

  test("SHA-256 empty string") {
    val hash = SHA256.hash(Array.emptyByteArray)
    assertEquals(
      toHex(hash),
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
  }

  test("SHA-256 'abc'") {
    val hash = SHA256.hash("abc".getBytes("UTF-8"))
    assertEquals(
      toHex(hash),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
  }

  test("SHA-256 longer message") {
    val hash = SHA256.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes("UTF-8"))
    assertEquals(
      toHex(hash),
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    )
  }
}
