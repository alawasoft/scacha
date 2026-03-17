# Scacha

ChaCha20 file encryptor, compiled to native via Scala Native.

## Features

- Pure Scala ChaCha20 stream cipher (RFC 8439)
- Pure Scala SHA-256 for passphrase key derivation
- Encrypt with a passphrase or a 256-bit hex key
- Parallel file processing with configurable concurrency
- Automatic file-type detection on decrypt (PNG, JPG, MP4, MOV, PDF, ZIP, AVI, GIF)
- Legacy NQVault XOR mode for `.vault` files
- No external crypto dependencies

## Prerequisites

- [Mill](https://mill-build.org/) build tool
- LLVM/clang (required by Scala Native for linking)

## Build

```sh
mill scacha.compile      # compile
mill scacha.test         # run tests
mill scacha.dist         # build native binary -> dist/scacha
```

## Usage

### Encrypt with passphrase

```sh
scacha encrypt -p "my secret phrase" -i photo.jpg
scacha encrypt -p "my secret phrase" -i photo.jpg -o /tmp/encrypted
```

### Decrypt with passphrase

```sh
scacha decrypt -p "my secret phrase" -i photo.jpg.scacha
```

### Encrypt/decrypt with hex key

```sh
scacha encrypt -k 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -i photo.jpg
scacha decrypt -k 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -i photo.jpg.scacha
```

### Batch folder processing

```sh
scacha encrypt -p "my secret phrase" -i ./photos -o ./encrypted -j 8
scacha decrypt -p "my secret phrase" -i ./encrypted -o ./decrypted -j 8
```

### Legacy XOR mode

```sh
scacha xor --mode encrypt --xor-key 39 -i photo.jpg
scacha xor --mode decrypt --xor-key 39 -i photo.jpg.vault
```

## `.scacha` file format

37-byte header followed by ChaCha20-encrypted data:

| Offset | Size | Field       | Description                              |
|--------|------|-------------|------------------------------------------|
| 0      | 8    | Magic       | `SCACHA01` (ASCII)                       |
| 8      | 1    | Key mode    | `0x00` = raw key, `0x01` = passphrase    |
| 9      | 16   | Salt        | CSPRNG salt (used with passphrase mode)  |
| 25     | 12   | Nonce       | CSPRNG nonce for ChaCha20                |
| 37     | ...  | Ciphertext  | ChaCha20 encrypted payload               |
