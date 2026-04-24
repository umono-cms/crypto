# crypto

`crypto` is a small Go package for deterministic, record-scoped encryption. It derives per-record AES-256-GCM keys from a single master key using HKDF-SHA256 and authenticates each record with its own ID.

## Features

- Generates cryptographically random 32-byte master keys
- Parses and exports keys as hex strings
- Derives a domain-scoped data key from the master key via HKDF-SHA256 (extract+expand)
- Derives a unique per-record encryption key from the data key via HKDF-SHA256 (expand only)
- Encrypts and decrypts with AES-256-GCM
- Authenticates the `recordID` as AES-GCM additional data (AAD) — decryption fails if the wrong ID is used

## Installation

```bash
go get github.com/umono-cms/crypto
```

## How It Works

```
master Key
    │
    ▼  HKDF-SHA256 extract+expand (info = application context, no salt)
data key
    │
    ├──▶  HKDF-SHA256 expand (info = "record-key:" || recordID)  ──▶  record key A
    ├──▶  HKDF-SHA256 expand (info = "record-key:" || recordID)  ──▶  record key B
    └──▶  ...
```

**Key derivation has two stages:**

1. `New(key, info)` runs a full HKDF extract+expand to produce the **data key**. The `info` value binds this key to a specific application domain (e.g. `"myapp:user-data"`). No salt is used; the master key is assumed to have sufficient entropy (32 random bytes from `crypto/rand`).

2. `Encrypt` and `Decrypt` each call an HKDF expand (no extract) on the data key, with `"record-key:" || recordID` as the info, to produce a **record key**. Each unique `recordID` produces a unique record key.

**Encryption output format:**

```
[ nonce (12 bytes) | ciphertext | GCM tag (16 bytes) ]
```

The nonce is randomly generated per call and prepended to the ciphertext. The `recordID` is passed as AES-GCM additional authenticated data (AAD) and must match exactly during decryption.

> **Warning:** Passing an empty or `nil` `recordID` is technically valid but means all records share the same derived key and no AAD binding. Always use a unique, non-empty ID per record.

## Usage

```go
package main

import (
	"fmt"
	"log"

	crypto "github.com/umono-cms/crypto"
)

func main() {
	// Generate a new random master key.
	key, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("master key (hex):", key.String())

	// Build a Secret scoped to your application domain.
	secret, err := crypto.New(key, []byte("myapp:user-data"))
	if err != nil {
		log.Fatal(err)
	}

	recordID := []byte("user-42")
	plaintext := []byte("sensitive payload")

	ciphertext, err := secret.Encrypt(plaintext, recordID)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := secret.Decrypt(ciphertext, recordID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(decrypted)) // sensitive payload
}
```

## Loading a Key From Hex

```go
hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

key, err := crypto.ParseHexString(hexKey)
if err != nil {
	// ErrInvalidHexFormat or ErrInvalidKeyLength
}
```

## Concurrency

`Secret` is safe for concurrent use. After construction, `New` sets the internal data key once and it is never modified. `Encrypt` and `Decrypt` derive ephemeral record keys per call without mutating shared state.

## API Reference

### Constants

| Name | Value | Description |
|------|-------|-------------|
| `KeySize` | `32` | Key size in bytes for master, data, and record keys |

### Types

| Type | Description |
|------|-------------|
| `Key` | Holds a 32-byte master key |
| `Secret` | Holds a derived data key scoped to an application context |

### Functions

| Signature | Description |
|-----------|-------------|
| `GenerateKey() (*Key, error)` | Generates a cryptographically random 32-byte master key |
| `ParseHexString(hexStr string) (*Key, error)` | Parses a 64-character hex string into a `Key` |
| `New(key *Key, info []byte) (*Secret, error)` | Derives a data key from the master key using `info` as domain context |

### Methods

| Signature | Description |
|-----------|-------------|
| `(*Key).String() string` | Returns the key as a lowercase hex string |
| `(*Secret).Encrypt(plaintext, recordID []byte) ([]byte, error)` | Encrypts `plaintext` with a key derived from `recordID`; returns `nonce \|\| ciphertext \|\| tag` |
| `(*Secret).Decrypt(ciphertext, recordID []byte) ([]byte, error)` | Decrypts ciphertext produced by `Encrypt`; fails if `recordID` does not match |

## Errors

| Error | Cause |
|-------|-------|
| `ErrInvalidKeyLength` | Parsed bytes are not exactly 32 bytes |
| `ErrInvalidHexFormat` | Input is not a valid hex string |
| `ErrCiphertextTooShort` | Ciphertext is shorter than the 12-byte GCM nonce |
| `ErrDecryptFailed` | Wrong key, wrong `recordID`, or corrupted ciphertext |
| `ErrEntropySource` | `crypto/rand` read failed |
| `ErrKeyDerivation` | HKDF derivation failed |

All errors support `errors.Is` wrapping.

## License

[MIT](./LICENSE)
