//go:build darwin && cgo

package clitoken

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/lstoll/oauth2ext/oidc"
	"github.com/lstoll/oauth2ext/tokencache"
	"golang.org/x/oauth2"
)

func init() {
	platformCaches = append(platformCaches, &KeychainCredentialCache{})
}

// KeychainCredentialCache uses the macOS keychain to store items. Items are
// keyed by the binary and issuer that they are for. It is intended for
// short/ephemeral caching, entries created via different executables will be
// removed rather than requiring the executable to be signed, or user input.
type KeychainCredentialCache struct{}

var _ tokencache.CredentialCache = &KeychainCredentialCache{}

func (k *KeychainCredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	ei, err := getKeychainExecutableInfo(issuer)
	if err != nil {
		return nil, fmt.Errorf("getting executable info: %w", err)
	}

	password, err := getKeychainPassword(ei.BinaryKey, ei.ServiceName, key)
	if err != nil {
		var kcErr *keychainError
		if errors.As(err, &kcErr) {
			if kcErr.status == C.errSecItemNotFound {
				// not found, just return nil
				return nil, nil
			}
		}
		return nil, fmt.Errorf("getting credential from keychain: %w", err)
	}

	var token oidc.TokenWithID
	if err := json.Unmarshal([]byte(password), &token); err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	return token.Token, nil
}

func (k *KeychainCredentialCache) Set(issuer, key string, token *oauth2.Token) error {
	b, err := json.Marshal(oidc.TokenWithID{Token: token})
	if err != nil {
		return fmt.Errorf("failed to encode token: %w", err)
	}

	ei, err := getKeychainExecutableInfo(issuer)
	if err != nil {
		return fmt.Errorf("getting executable info: %w", err)
	}

	// we make the label read a little better in the UI
	lbl := fmt.Sprintf("%s: %s (%s)", ei.Name, issuer, key)

	if err := setKeychainPassword(ei.BinaryKey, lbl, ei.ServiceName, key, string(b)); err != nil {
		return fmt.Errorf("saving credential to keychain: %w", err)
	}

	return nil
}

func (k *KeychainCredentialCache) Available() bool {
	// should always be this, but check anyway
	return runtime.GOOS == "darwin"
}

type keychainExecutableInfo struct {
	// BinaryKey uniquely identifies this compiled binary by it's creation
	// time.This is fast to get, and should uniquely represent the process that
	// created the keychain entry.
	BinaryKey []byte
	// Name is the basename of this executable
	Name string
	// ServiceName is the issuer with an execuable-specific prefix, to handle
	// multiple applications saving items for the same idp.
	ServiceName string
}

// getKeychainProcessInfo builds the process/binary specific info used for
// accessing the keychain
func getKeychainExecutableInfo(issuer string) (keychainExecutableInfo, error) {
	execPath, err := os.Executable()
	if err != nil {
		return keychainExecutableInfo{}, fmt.Errorf("looking up executable: %w", err)
	}

	fileInfo, err := os.Stat(execPath)
	if err != nil {
		return keychainExecutableInfo{}, fmt.Errorf("getting executable info: %w", err)
	}

	stat := fileInfo.Sys().(*syscall.Stat_t)

	bi := make([]byte, 8)
	binary.LittleEndian.PutUint64(bi, uint64(stat.Ctimespec.Nano()))

	return keychainExecutableInfo{
		BinaryKey:   bi,
		Name:        fileInfo.Name(),
		ServiceName: fileInfo.Name() + ";" + issuer,
	}, nil
}

var (
	nilCFStringRef C.CFStringRef
)

type keychainError struct {
	status C.OSStatus
}

func (e *keychainError) Error() string {
	cfError := C.SecCopyErrorMessageString(e.status, nil)
	if cfError != nilCFStringRef {
		defer C.CFRelease(C.CFTypeRef(cfError))
		return fmt.Sprintf("%s (%d)", cfStringToString(cfError), e.status)
	}
	return fmt.Sprintf("Unknown keychain error: %d", e.status)
}

func newKeychainError(status C.OSStatus) error {
	if status == C.errSecSuccess {
		return nil
	}
	return &keychainError{status: status}
}

// setKeychainPassword stores an item in the keychain. If it doesn't exist it
// will be created, if it does the password field will be updated. binaryKey is
// used to uniqely identify this compiled binary, to avoid prompting for unlock
// when a different binary created the item.
//
//nolint:govet // the possible unsafe use is fine here
func setKeychainPassword(binaryKey []byte, label, service, account, password string) error {
	labelRef := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(label), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(labelRef))
	serviceRef := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(service), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(serviceRef))
	accountRef := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(account), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(accountRef))

	passwordBytes := []byte(password)
	passwordRef := C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&passwordBytes[0])), C.CFIndex(len(passwordBytes)))
	defer C.CFRelease(C.CFTypeRef(passwordRef))

	binaryKeyRef := C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&binaryKey[0])), C.CFIndex(len(binaryKey)))
	defer C.CFRelease(C.CFTypeRef(binaryKeyRef))

	// always try and delete the item first, to ensure it is set for our app. If
	// we update, it doesn't seem to update the ACL as well.
	if err := deleteKeychainPassword(service, account); err != nil {
		var kcErr *keychainError
		if !errors.As(err, &kcErr) || kcErr.status != C.errSecItemNotFound {
			return fmt.Errorf("deleting keychain item: %w", err)
		}
	}

	query := C.CFDictionaryCreateMutable(C.kCFAllocatorDefault, 0, &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
	defer C.CFRelease(C.CFTypeRef(query))

	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassGenericPassword))
	// these two make up the primary key in the keychain
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrService), unsafe.Pointer(serviceRef))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrAccount), unsafe.Pointer(accountRef))
	// and these are the fields we want to set
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrLabel), unsafe.Pointer(labelRef))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecValueData), unsafe.Pointer(passwordRef))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrGeneric), unsafe.Pointer(binaryKeyRef))
	status := C.SecItemAdd(C.CFDictionaryRef(query), nil)

	return newKeychainError(status)
}

//nolint:govet // the possible unsafe use is fine here
func getKeychainPassword(binaryKey []byte, service, account string) (string, error) {
	serviceRef := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(service), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(serviceRef))
	accountRef := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(account), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(accountRef))

	query := C.CFDictionaryCreateMutable(C.kCFAllocatorDefault, 0, &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
	defer C.CFRelease(C.CFTypeRef(query))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassGenericPassword))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrService), unsafe.Pointer(serviceRef))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrAccount), unsafe.Pointer(accountRef))
	// get the attributes first, so we can check if it aligns with this
	// executable
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecReturnAttributes), unsafe.Pointer(C.kCFBooleanTrue))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecMatchLimit), unsafe.Pointer(C.kSecMatchLimitOne))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &result)
	if err := newKeychainError(status); err != nil {
		return "", fmt.Errorf("reading from keychain: %w", err)
	}
	defer C.CFRelease(result)

	count := C.CFDictionaryGetCount(C.CFDictionaryRef(result))
	if count == 0 {
		return "", fmt.Errorf("getting attribute info returned no items")
	}

	keys := make([]C.CFTypeRef, count)
	values := make([]C.CFTypeRef, count)
	C.CFDictionaryGetKeysAndValues(C.CFDictionaryRef(result), (*unsafe.Pointer)(unsafe.Pointer(&keys[0])), (*unsafe.Pointer)(unsafe.Pointer(&values[0])))
	attrs := make(map[C.CFTypeRef]C.CFTypeRef, count)
	for i := C.CFIndex(0); i < count; i++ {
		attrs[keys[i]] = values[i]
	}

	abk, ok := attrs[C.CFTypeRef(C.kSecAttrGeneric)]
	if !ok {
		// record has no binary key, remove and treat as not found
		_ = deleteKeychainPassword(service, account)
		return "", newKeychainError(C.errSecItemNotFound)
	}
	abkLen := C.CFDataGetLength(C.CFDataRef(abk))
	abkBytes := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(C.CFDataRef(abk))), C.int(abkLen))

	if !bytes.Equal(binaryKey, abkBytes) {
		// record created by a different binary, remove and treat as not found
		_ = deleteKeychainPassword(service, account)
		return "", newKeychainError(C.errSecItemNotFound)
	}

	// if we're here, there's an item that was created by this binary. re-read it, with the data
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecReturnAttributes), unsafe.Pointer(C.kCFBooleanFalse))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecReturnData), unsafe.Pointer(C.kCFBooleanTrue))

	var dataResult C.CFTypeRef
	status = C.SecItemCopyMatching(C.CFDictionaryRef(query), &dataResult)
	if err := newKeychainError(status); err != nil {
		return "", fmt.Errorf("reading with data from keychain: %w", err)
	}
	defer C.CFRelease(dataResult)

	length := C.CFDataGetLength(C.CFDataRef(dataResult))
	bytes := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(C.CFDataRef(dataResult))), C.int(length))

	return string(bytes), nil
}

//nolint:govet // the possible unsafe use is fine here
func deleteKeychainPassword(service, account string) error {
	serviceRef := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(service), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(serviceRef))
	accountRef := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(account), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(accountRef))

	query := C.CFDictionaryCreateMutable(C.kCFAllocatorDefault, 0, &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
	defer C.CFRelease(C.CFTypeRef(query))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassGenericPassword))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrService), unsafe.Pointer(serviceRef))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrAccount), unsafe.Pointer(accountRef))

	return newKeychainError(C.SecItemDelete(C.CFDictionaryRef(query)))
}

func cfStringToString(cfString C.CFStringRef) string {
	cStr := C.CFStringGetCStringPtr(cfString, C.kCFStringEncodingUTF8)
	if cStr != nil {
		return C.GoString(cStr)
	}

	length := C.CFStringGetLength(cfString)
	maxSize := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8)
	buffer := make([]C.char, maxSize)
	if result := C.CFStringGetCString(cfString, (*C.char)(unsafe.Pointer(&buffer[0])), maxSize, C.kCFStringEncodingUTF8); result == C.true {
		return C.GoString(&buffer[0])
	}

	return ""
}
