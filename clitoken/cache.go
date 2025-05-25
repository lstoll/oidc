package clitoken

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"

	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/tokencache"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/oauth2"
	"golang.org/x/term"
)

var (
	// platformCache is registered by any platform specific caches, and should be
	// preferred
	platformCaches []tokencache.CredentialCache
	// genericCaches is a list in preference order of non-platform specific caches
	genericCaches = []tokencache.CredentialCache{&KeychainCLICredentialCache{}, &EncryptedFileCredentialCache{}}
)

type PassphrasePromptFunc func(prompt string) (passphrase string, err error)

// BestCredentialCache returns the most preferred available credential client
// for the platform and environment.
func BestCredentialCache() tokencache.CredentialCache {
	for _, c := range append(platformCaches, genericCaches...) {
		if c.Available() {
			return c
		}
	}

	return &NullCredentialCache{}
}

// KeychainCLICredentialCache uses /usr/bin/security to store items. This is
// flexible and doesn't require CGO, however any other process can read the
// items via the command
type KeychainCLICredentialCache struct{}

var _ tokencache.CredentialCache = &KeychainCLICredentialCache{}

func (k *KeychainCLICredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	cmd := exec.Command(
		"/usr/bin/security",
		"find-generic-password",
		"-s", issuer,
		"-a", key,
		"-w",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		if bytes.Contains(out, []byte("could not be found")) {
			return nil, nil
		}

		return nil, fmt.Errorf("%s: %w", string(out), err)
	}

	var token oidc.TokenWithID
	if err := json.Unmarshal(out, &token); err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	return token.Token, nil
}

func (k *KeychainCLICredentialCache) Set(issuer, key string, token *oauth2.Token) error {
	b, err := json.Marshal(oidc.TokenWithID{Token: token})
	if err != nil {
		return fmt.Errorf("failed to encode token: %w", err)
	}

	cmd := exec.Command(
		"/usr/bin/security",
		"add-generic-password",
		"-s", issuer,
		"-a", key,
		"-w", string(b),
		"-U",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", string(out), err)
	}

	return nil
}

func (k *KeychainCLICredentialCache) Available() bool {
	if runtime.GOOS != "darwin" {
		return false
	}

	_, err := os.Stat("/usr/bin/security")

	return err == nil
}

const encryptedFileKeySize = 32
const encryptedFileNonceSize = 24
const encryptedFileSaltSize = 8

type EncryptedFileCredentialCache struct {
	// Dir is the path where encrypted cache files will be stored.
	// If empty, to oidc-cache in the os.UserCacheDir
	Dir string

	// PassphrasePromptFunc is a function that prompts the user to enter a
	// passphrase used to encrypt and decrypt a file.
	PassphrasePromptFunc
}

var _ tokencache.CredentialCache = &EncryptedFileCredentialCache{}

func (e *EncryptedFileCredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	dir, err := e.resolveDir()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	filename := path.Join(dir, e.cacheFilename(issuer, key))
	contents, err := os.ReadFile(filename)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to read file %q: %w", filename, err)
	}

	if len(contents) < encryptedFileNonceSize {
		return nil, fmt.Errorf("file %q missing nonce", filename)
	}

	// File structure is:
	// 24 bytes: nonce
	// 8 bytes: salt
	// N bytes: ciphertext
	var nonce [encryptedFileNonceSize]byte
	copy(nonce[:], contents)
	var salt [encryptedFileSaltSize]byte
	copy(salt[:], contents[encryptedFileNonceSize:])
	ciphertext := contents[encryptedFileNonceSize+encryptedFileSaltSize:]

	passphrase, err := (e.promptFuncOrDefault())(fmt.Sprintf("Enter passphrase for decrypting %s token", issuer))
	if err != nil {
		return nil, err
	}

	ek, err := e.passphraseToKey(passphrase, salt)
	if err != nil {
		return nil, err
	}

	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &ek)
	if !ok {
		return nil, nil
	}

	token := new(oauth2.Token)
	if err := json.Unmarshal(plaintext, token); err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	return token, nil
}

func (e *EncryptedFileCredentialCache) Set(issuer, key string, token *oauth2.Token) error {
	dir, err := e.resolveDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	var nonce [encryptedFileNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	var salt [encryptedFileSaltSize]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	passphrase, err := e.promptFuncOrDefault()(fmt.Sprintf("Enter passphrase for encrypting %s token", issuer))
	if err != nil {
		return err
	}

	ek, err := e.passphraseToKey(passphrase, salt)
	if err != nil {
		return err
	}

	plaintext, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to encode token: %w", err)
	}

	ciphertext := secretbox.Seal(nil, plaintext, &nonce, &ek)

	// Writes to a bytes.Buffer always succeed (or panic)
	buf := new(bytes.Buffer)
	_, _ = buf.Write(nonce[:])
	_, _ = buf.Write(salt[:])
	_, _ = buf.Write(ciphertext)

	filename := path.Join(dir, e.cacheFilename(issuer, key))
	if err := os.WriteFile(filename, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write file %q: %w", filename, err)
	}

	return nil
}

func (e *EncryptedFileCredentialCache) Available() bool {
	return true
}

func (e *EncryptedFileCredentialCache) resolveDir() (string, error) {
	dir := e.Dir
	if dir == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("could not find user cache dir: %w", err)
		}
		dir = path.Join(cacheDir, "oidc-cache")
	}

	if strings.HasPrefix(dir, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("unable to determine home directory: %w", err)
		}

		dir = path.Join(home, dir[2:])
	}

	return dir, nil
}

func (e *EncryptedFileCredentialCache) cacheFilename(issuer, key string) string {
	// A hash is used to avoid special characters in filenames
	hsh := sha256.Sum256(
		fmt.Appendf(nil,
			"%s;%s",
			issuer,
			key,
		),
	)

	return hex.EncodeToString(hsh[:]) + ".enc"
}

func (e *EncryptedFileCredentialCache) passphraseToKey(passphrase string, salt [encryptedFileSaltSize]byte) ([encryptedFileKeySize]byte, error) {
	var akey [encryptedFileKeySize]byte

	key, err := scrypt.Key([]byte(passphrase), salt[:], 1<<15, 8, 1, encryptedFileKeySize)
	if err != nil {
		return akey, err
	}

	copy(akey[:], key)
	return akey, nil
}

func (e *EncryptedFileCredentialCache) promptFuncOrDefault() PassphrasePromptFunc {
	if e.PassphrasePromptFunc != nil {
		return e.PassphrasePromptFunc
	}

	return func(prompt string) (string, error) {
		if cp := os.Getenv("OIDC_CACHE_PASSPHRASE_DO_NOT_USE"); cp != "" {
			return cp, nil
		}

		fmt.Fprintf(os.Stderr, "%s: ", prompt)
		passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		fmt.Fprintln(os.Stderr)

		return string(passphrase), nil
	}
}

// MemoryWriteThroughCredentialCache is a write-through cache for another
// underlying CredentialCache. If a credential has been previously requested
// from the underlying store, it is read from memory the next time it is
// requested.
//
// MemoryWriteThroughCredentialCache is useful when the underlying store
// requires user input (e.g., a passphrase) or is otherwise expensive.
type MemoryWriteThroughCredentialCache struct {
	tokencache.CredentialCache

	m map[string]*oauth2.Token
}

var _ tokencache.CredentialCache = &MemoryWriteThroughCredentialCache{}

func (c *MemoryWriteThroughCredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	cacheKey := c.cacheKey(issuer, key)

	if token := c.m[cacheKey]; token != nil {
		return token, nil
	}

	token, err := c.CredentialCache.Get(issuer, key)
	if err != nil {
		return nil, err
	}

	if c.m == nil {
		c.m = make(map[string]*oauth2.Token)
	}
	c.m[cacheKey] = token

	return token, nil
}

func (c *MemoryWriteThroughCredentialCache) Set(issuer, key string, token *oauth2.Token) error {
	err := c.CredentialCache.Set(issuer, key, token)
	if err != nil {
		return err
	}

	cacheKey := c.cacheKey(issuer, key)

	if c.m == nil {
		c.m = make(map[string]*oauth2.Token)
	}
	c.m[cacheKey] = token

	return nil
}

func (c *MemoryWriteThroughCredentialCache) Available() bool {
	return true
}

func (c *MemoryWriteThroughCredentialCache) cacheKey(issuer, key string) string {
	return fmt.Sprintf(
		"%s;%s",
		issuer,
		key,
	)
}

// NullCredentialCache will not cache tokens. Used it to opt out of caching.
type NullCredentialCache struct{}

var _ tokencache.CredentialCache = &NullCredentialCache{}

func (c *NullCredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	return nil, nil
}

func (c *NullCredentialCache) Set(issuer, key string, token *oauth2.Token) error {
	return nil
}

func (c *NullCredentialCache) Available() bool {
	return true
}
