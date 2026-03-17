package com.alawasoft.scacha

import cats.effect.IO
import cats.effect.syntax.concurrent.*
import cats.syntax.all.*
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.{Files, Path, StandardOpenOption}
import scala.jdk.CollectionConverters.*

enum Mode {
  case Encrypt, Decrypt
}

sealed trait KeySource
object KeySource {
  case class RawKey(key: Array[Byte]) extends KeySource
  case class Passphrase(value: String) extends KeySource
}

object Engine {

  private val ChunkSize: Int = 64 * 1024

  def encryptFile(inputPath: Path, outputFolder: Path, keySource: KeySource): IO[Option[Path]] = {
    IO.blocking {
      val nonce = new Array[Byte](12)
      SecureRng.nextBytes(nonce)

      val (key, keyMode, salt) = keySource match {
        case KeySource.RawKey(k) =>
          (k, ScachaFormat.KeyModeRaw, new Array[Byte](16))
        case KeySource.Passphrase(pp) =>
          val s = new Array[Byte](16)
          SecureRng.nextBytes(s)
          val k = KeyDerivation.fromPassphrase(pp, s)
          (k, ScachaFormat.KeyModePassphrase, s)
      }

      val outputPath = outputFolder.resolve(inputPath.getFileName.toString + ".scacha")
      val inCh = FileChannel.open(inputPath, StandardOpenOption.READ)
      try {
        val outCh = FileChannel.open(
          outputPath,
          StandardOpenOption.WRITE,
          StandardOpenOption.CREATE,
          StandardOpenOption.TRUNCATE_EXISTING
        )
        try {
          ScachaFormat.writeHeader(outCh, keyMode, salt, nonce)
          streamProcess(inCh, outCh, key, nonce)
        } finally {
          outCh.close()
        }
      } finally {
        inCh.close()
      }
      println(s"Encrypted ${inputPath.getFileName} -> ${outputPath.getFileName}")
      Some(outputPath)
    }.handleErrorWith { e =>
      IO.println(s"Error encrypting ${inputPath.getFileName}: ${e.getClass.getSimpleName}: ${e.getMessage}").as(None)
    }
  }

  def decryptFile(inputPath: Path, outputFolder: Path, keySource: KeySource): IO[Option[Path]] = {
    IO.blocking {
      val inCh = FileChannel.open(inputPath, StandardOpenOption.READ)
      try {
        ScachaFormat.readHeader(inCh) match {
          case Left(err) =>
            println(s"Skipped ${inputPath.getFileName} ($err)")
            None
          case Right(header) =>
            val maybeKey: Option[Array[Byte]] = (header.keyMode, keySource) match {
              case (ScachaFormat.KeyModePassphrase, KeySource.Passphrase(pp)) =>
                Some(KeyDerivation.fromPassphrase(pp, header.salt))
              case (ScachaFormat.KeyModePassphrase, KeySource.RawKey(_)) =>
                println(s"Skipped ${inputPath.getFileName} (encrypted with passphrase but raw key provided)")
                None
              case (_, KeySource.RawKey(k)) => Some(k)
              case (_, KeySource.Passphrase(_)) =>
                println(s"Skipped ${inputPath.getFileName} (encrypted with raw key but passphrase provided)")
                None
            }

            maybeKey match {
              case None => None
              case Some(key) =>
                val fileSize = inCh.size() - ScachaFormat.HeaderSize
                val previewSize = math.min(128, fileSize).toInt
                val previewBuf = ByteBuffer.allocate(previewSize)
                inCh.read(previewBuf)
                previewBuf.flip()
                val previewBytes = new Array[Byte](previewSize)
                previewBuf.get(previewBytes)
                val decryptedPreview = ChaCha20.xorStream(key, header.nonce, 0, previewBytes)

                val ext = FileSignature.detect(IArray.unsafeFromArray(decryptedPreview)).getOrElse(".bin")
                val baseName = {
                  val name = inputPath.getFileName.toString
                  if (name.endsWith(".scacha")) name.dropRight(7) else s"decrypted_$name"
                }
                val outputPath = outputFolder.resolve(baseName + ext)

                inCh.position(ScachaFormat.HeaderSize.toLong)
                val outCh = FileChannel.open(
                  outputPath,
                  StandardOpenOption.WRITE,
                  StandardOpenOption.CREATE,
                  StandardOpenOption.TRUNCATE_EXISTING
                )
                try {
                  streamProcess(inCh, outCh, key, header.nonce)
                } finally {
                  outCh.close()
                }
                println(s"Decrypted ${inputPath.getFileName} -> ${outputPath.getFileName}")
                Some(outputPath)
            }
        }
      } finally {
        inCh.close()
      }
    }.handleErrorWith { e =>
      IO.println(s"Error decrypting ${inputPath.getFileName}: ${e.getClass.getSimpleName}: ${e.getMessage}").as(None)
    }
  }

  def xorFile(inputPath: Path, outputFolder: Path, xorKey: Byte, mode: Mode): IO[Option[Path]] = {
    IO.blocking {
      val inCh = FileChannel.open(inputPath, StandardOpenOption.READ)
      try {
        val fileSize = inCh.size()
        val headerSize = math.min(128, fileSize).toInt
        val headerBuf = ByteBuffer.allocate(headerSize)
        inCh.read(headerBuf)
        headerBuf.flip()
        val headerBytes = new Array[Byte](headerSize)
        headerBuf.get(headerBytes)
        val xoredHeader = xorHeader(headerBytes, xorKey)

        mode match {
          case Mode.Decrypt =>
            FileSignature.detect(IArray.unsafeFromArray(xoredHeader)) match {
              case Some(ext) =>
                val outputPath = outputFolder.resolve(s"decrypted_${inputPath.getFileName}$ext")
                writeXorOutput(outputPath, xoredHeader, inCh, fileSize)
                println(s"Decrypted ${inputPath.getFileName} -> ${outputPath.getFileName}")
                Some(outputPath)
              case None =>
                println(s"Skipped ${inputPath.getFileName} (unrecognized file type)")
                None
            }
          case Mode.Encrypt =>
            val outputPath = outputFolder.resolve(s"${inputPath.getFileName}.vault")
            writeXorOutput(outputPath, xoredHeader, inCh, fileSize)
            println(s"Encrypted ${inputPath.getFileName} -> ${outputPath.getFileName}")
            Some(outputPath)
        }
      } finally {
        inCh.close()
      }
    }.handleErrorWith { e =>
      IO.println(s"Error processing ${inputPath.getFileName}: ${e.getClass.getSimpleName}: ${e.getMessage}").as(None)
    }
  }

  def run(
    input: Path,
    output: Path,
    parallelism: Int,
    process: (Path, Path) => IO[Option[Path]]
  ): IO[Int] = {
    IO.blocking(Files.isDirectory(input)).flatMap {
      case true =>
        for {
          _ <- IO.blocking(Files.createDirectories(output))
          files <- IO.blocking {
            val stream = Files.newDirectoryStream(input)
            try {
              stream.asScala.toList.filter(Files.isRegularFile(_))
            } finally {
              stream.close()
            }
          }
          results <- files.parTraverseN(parallelism)(f => process(f, output))
        } yield results.count(_.isDefined)
      case false =>
        val outputDir = if (Files.isDirectory(output)) {
          output
        } else {
          output.getParent match {
            case null => input.toAbsolutePath.getParent
            case p    => p
          }
        }
        for {
          _ <- IO.blocking(Files.createDirectories(outputDir))
          result <- process(input, outputDir)
        } yield if (result.isDefined) 1 else 0
    }
  }

  private def streamProcess(inCh: FileChannel, outCh: FileChannel, key: Array[Byte], nonce: Array[Byte]): Unit = {
    val buf = ByteBuffer.allocate(ChunkSize)
    var counter = 0
    var bytesRead = inCh.read(buf)
    while (bytesRead > 0) {
      buf.flip()
      val chunk = new Array[Byte](bytesRead)
      buf.get(chunk)
      val processed = ChaCha20.xorStream(key, nonce, counter, chunk)
      outCh.write(ByteBuffer.wrap(processed))
      counter += (bytesRead + 63) / 64
      buf.clear()
      bytesRead = inCh.read(buf)
    }
  }

  private def xorHeader(data: Array[Byte], key: Byte): Array[Byte] = {
    val result = new Array[Byte](data.length)
    var i = 0
    while (i < data.length) {
      result(i) = (data(i) ^ key).toByte
      i += 1
    }
    result
  }

  private def writeXorOutput(outputPath: Path, header: Array[Byte], inputChannel: FileChannel, fileSize: Long): Unit = {
    val outCh = FileChannel.open(
      outputPath,
      StandardOpenOption.WRITE,
      StandardOpenOption.CREATE,
      StandardOpenOption.TRUNCATE_EXISTING
    )
    try {
      outCh.write(ByteBuffer.wrap(header))
      if (fileSize > 128) {
        inputChannel.position(128)
        val buf = ByteBuffer.allocate(1024 * 1024)
        var bytesRead = inputChannel.read(buf)
        while (bytesRead > 0) {
          buf.flip()
          outCh.write(buf)
          buf.clear()
          bytesRead = inputChannel.read(buf)
        }
      }
    } finally {
      outCh.close()
    }
  }
}
