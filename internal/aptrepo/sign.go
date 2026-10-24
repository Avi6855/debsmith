// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package aptrepo

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Sign produces an InRelease file and an armored detached Release.gpg.
func Sign(release []byte, keyPath, passphrase string, epoch time.Time) ([]byte, []byte, error) {
	if keyPath == "" {
		return nil, nil, nil
	}

	entity, err := LoadSigner(keyPath, passphrase)
	if err != nil {
		return nil, nil, err
	}

	config := signatureConfig(epoch)

	inRelease, err := clearsignEntity(entity, release, config)
	if err != nil {
		return nil, nil, err
	}

	var detached bytes.Buffer

	//nolint:staticcheck // v1 armored detached signatures are still the public API.
	if err := openpgp.ArmoredDetachSign(&detached, entity, bytes.NewReader(release), config); err != nil {
		return nil, nil, fmt.Errorf("aptrepo: sign Release: %w", err)
	}

	return inRelease, detached.Bytes(), nil
}

// Clearsign signs a document, returning it unchanged when keyPath is empty.
func Clearsign(message []byte, keyPath, passphrase string, epoch time.Time) ([]byte, error) {
	if keyPath == "" {
		return message, nil
	}

	entity, err := LoadSigner(keyPath, passphrase)
	if err != nil {
		return nil, err
	}

	return clearsignEntity(entity, message, signatureConfig(epoch))
}

func signatureConfig(epoch time.Time) *packet.Config {
	return &packet.Config{
		Time: func() time.Time {
			return epoch
		},
	}
}

func clearsignEntity(entity *openpgp.Entity, message []byte,
	config *packet.Config,
) ([]byte, error) {
	var signed bytes.Buffer

	plaintext, err := clearsign.Encode(&signed, entity.PrivateKey, config)
	if err != nil {
		return nil, fmt.Errorf("aptrepo: clearsign document: %w", err)
	}

	if _, err := plaintext.Write(message); err != nil {
		return nil, fmt.Errorf("aptrepo: write clearsigned document: %w", err)
	}

	if err := plaintext.Close(); err != nil {
		return nil, fmt.Errorf("aptrepo: finish clearsigned document: %w", err)
	}

	return signed.Bytes(), nil
}

// LoadSigner reads an armored or binary OpenPGP private key.
func LoadSigner(path string, passphrase string) (*openpgp.Entity, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("aptrepo: read signing key: %w", err)
	}

	var entities openpgp.EntityList

	if bytes.Contains(content, []byte("-----BEGIN PGP")) {
		entities, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(content))
	} else {
		entities, err = openpgp.ReadKeyRing(bytes.NewReader(content))
	}

	if err != nil {
		return nil, fmt.Errorf("aptrepo: parse signing key: %w", err)
	}

	if len(entities) == 0 {
		return nil, errors.New("aptrepo: signing key contains no entities")
	}

	entity := entities[0]
	if entity.PrivateKey == nil {
		return nil, errors.New("aptrepo: signing key has no private key")
	}

	if err := decryptKey(entity, passphrase); err != nil {
		return nil, err
	}

	return entity, nil
}

func decryptKey(entity *openpgp.Entity, passphrase string) error {
	keys := []*packet.PrivateKey{entity.PrivateKey}

	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil {
			keys = append(keys, subkey.PrivateKey)
		}
	}

	for _, key := range keys {
		if !key.Encrypted {
			continue
		}

		if passphrase == "" {
			return errors.New("aptrepo: signing key is encrypted; pass --passphrase-file or " +
				"DEBSMITH_GPG_PASSPHRASE")
		}

		if err := key.Decrypt([]byte(passphrase)); err != nil {
			return fmt.Errorf("aptrepo: decrypt signing key: %w", err)
		}
	}

	return nil
}

// ReadPassphrase reads a passphrase file, trimming a single trailing newline.
func ReadPassphrase(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("aptrepo: read passphrase file: %w", err)
	}

	return strings.TrimRight(string(content), "\r\n"), nil
}
