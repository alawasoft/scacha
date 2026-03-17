package com.alawasoft.scacha

object FileSignature {

  case class Signature(bytes: IArray[Byte], extension: String)

  val All: List[Signature] = List(
    Signature(IArray(0.toByte, 0.toByte, 0.toByte, 0x14.toByte, 'f'.toByte, 't'.toByte, 'y'.toByte, 'p'.toByte, 'q'.toByte, 't'.toByte), ".mov"),
    Signature(IArray(0.toByte, 0.toByte, 0.toByte, 0x14.toByte, 'f'.toByte, 't'.toByte, 'y'.toByte, 'p'.toByte), ".mp4"),
    Signature(IArray(0.toByte, 0.toByte, 0.toByte, 0x18.toByte, 'f'.toByte, 't'.toByte, 'y'.toByte, 'p'.toByte), ".mp4"),
    Signature(IArray(0.toByte, 0.toByte, 0.toByte, 0x1c.toByte, 'f'.toByte, 't'.toByte, 'y'.toByte, 'p'.toByte), ".mp4"),
    Signature(IArray(0x89.toByte, 'P'.toByte, 'N'.toByte, 'G'.toByte), ".png"),
    Signature(IArray('P'.toByte, 'K'.toByte, 0x03.toByte, 0x04.toByte), ".zip"),
    Signature(IArray('R'.toByte, 'I'.toByte, 'F'.toByte, 'F'.toByte), ".avi"),
    Signature(IArray(0xFF.toByte, 0xD8.toByte, 0xFF.toByte), ".jpg"),
    Signature(IArray('G'.toByte, 'I'.toByte, 'F'.toByte, '8'.toByte), ".gif"),
    Signature(IArray('%'.toByte, 'P'.toByte, 'D'.toByte, 'F'.toByte), ".pdf")
  )

  def detect(header: IArray[Byte]): Option[String] = {
    All.find { sig =>
      header.length >= sig.bytes.length &&
        header.take(sig.bytes.length).sameElements(sig.bytes)
    }.map(_.extension)
  }
}
