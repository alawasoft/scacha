package com.alawasoft.scacha

import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all.*
import com.monovore.decline.*
import java.nio.file.Path

object Main extends IOApp {

  private val hexKeyOpt = Opts.option[String]("key", "256-bit key as 64 hex characters", short = "k")
    .mapValidated { hex =>
      KeyDerivation.fromHex(hex) match {
        case Right(k) => k.validNel
        case Left(e)  => e.invalidNel
      }
    }

  private val passphraseOpt = Opts.option[String]("passphrase", "Passphrase for key derivation", short = "p")

  private val keySourceOpt: Opts[KeySource] =
    hexKeyOpt.map(k => KeySource.RawKey(k): KeySource) orElse
      passphraseOpt.map(p => KeySource.Passphrase(p): KeySource)

  private val xorKeyOpt = Opts.option[Int]("xor-key", "XOR key (0-255)")
    .withDefault(39)
    .validate("Key must be 0-255")(k => k >= 0 && k <= 255)
    .map(_.toByte)

  private val modeOpt = Opts.option[String]("mode", "encrypt or decrypt")
    .mapValidated {
      case "encrypt" => Mode.Encrypt.validNel
      case "decrypt" => Mode.Decrypt.validNel
      case other     => s"Invalid mode: $other (must be encrypt or decrypt)".invalidNel
    }

  private val inputOpt = Opts.option[String]("input", "Input file or folder", short = "i")
    .map(Path.of(_))

  private val outputOpt = Opts.option[String]("output", "Output folder (defaults to input location)", short = "o")
    .orNone
    .map(_.map(Path.of(_)))

  private val jobsOpt = Opts.option[Int]("jobs", "Parallelism level", short = "j")
    .withDefault(Runtime.getRuntime.availableProcessors())

  private val encryptCmd = Opts.subcommand("encrypt", "Encrypt files with ChaCha20") {
    (keySourceOpt, inputOpt, outputOpt, jobsOpt).tupled
  }

  private val decryptCmd = Opts.subcommand("decrypt", "Decrypt .scacha files with ChaCha20") {
    (keySourceOpt, inputOpt, outputOpt, jobsOpt).tupled
  }

  private val xorCmd = Opts.subcommand("xor", "Legacy NQVault XOR encrypt/decrypt") {
    (xorKeyOpt, inputOpt, outputOpt, jobsOpt, modeOpt).tupled
  }

  sealed trait Args
  case class EncryptArgs(keySource: KeySource, input: Path, output: Option[Path], jobs: Int) extends Args
  case class DecryptArgs(keySource: KeySource, input: Path, output: Option[Path], jobs: Int) extends Args
  case class XorArgs(xorKey: Byte, input: Path, output: Option[Path], jobs: Int, mode: Mode) extends Args

  private val command = Command(
    name = "scacha",
    header = "Scacha - ChaCha20 file encryptor/decryptor"
  ) {
    encryptCmd.map(t => EncryptArgs(t._1, t._2, t._3, t._4): Args) orElse
      decryptCmd.map(t => DecryptArgs(t._1, t._2, t._3, t._4): Args) orElse
      xorCmd.map(t => XorArgs(t._1, t._2, t._3, t._4, t._5): Args)
  }

  override def run(args: List[String]): IO[ExitCode] = {
    command.parse(args) match {
      case Right(parsed) =>
        parsed match {
          case EncryptArgs(keySource, input, maybeOutput, jobs) =>
            val output = resolveOutput(input, maybeOutput)
            val process = (path: Path, outDir: Path) =>
              Engine.encryptFile(path, outDir, keySource)
            for {
              count <- Engine.run(input, output, jobs, process)
              _ <- IO.println(s"Successfully encrypted $count files.")
            } yield ExitCode.Success

          case DecryptArgs(keySource, input, maybeOutput, jobs) =>
            val output = resolveOutput(input, maybeOutput)
            val process = (path: Path, outDir: Path) =>
              Engine.decryptFile(path, outDir, keySource)
            for {
              count <- Engine.run(input, output, jobs, process)
              _ <- IO.println(s"Successfully decrypted $count files.")
            } yield ExitCode.Success

          case XorArgs(xorKey, input, maybeOutput, jobs, mode) =>
            val output = resolveOutput(input, maybeOutput)
            val verb = if (mode == Mode.Encrypt) "encrypted" else "decrypted"
            val process = (path: Path, outDir: Path) =>
              Engine.xorFile(path, outDir, xorKey, mode)
            for {
              count <- Engine.run(input, output, jobs, process)
              _ <- IO.println(s"Successfully $verb $count files.")
            } yield ExitCode.Success
        }
      case Left(help) =>
        IO.consoleForIO.println(help.toString).as(ExitCode.Error)
    }
  }

  private def resolveOutput(input: Path, maybeOutput: Option[Path]): Path = {
    maybeOutput.getOrElse {
      if (java.nio.file.Files.isDirectory(input)) input
      else input.toAbsolutePath.getParent
    }
  }
}
