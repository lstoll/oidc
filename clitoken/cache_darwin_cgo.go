//go:build darwin && cgo

package clitoken

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/tokencache"
	"golang.org/x/oauth2"
)

func init() {
	platformCaches = append(platformCaches, &KeychainCredentialCache{})
}

type KeychainCredentialCache struct{}

var _ tokencache.CredentialCache = &KeychainCredentialCache{}

func (k *KeychainCredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	password, err := getKeychainPassword(issuer, key)
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

	if err := setKeychainPassword(issuer, key, string(b)); err != nil {
		return fmt.Errorf("saving credential to keychain: %w", err)
	}

	return nil
}

func (k *KeychainCredentialCache) Available() bool {
	// should always be this, but check anyway
	return runtime.GOOS == "darwin"
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

//nolint:govet // the possible unsafe use is fine here
func setKeychainPassword(service, account, password string) error {
	serviceRef := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(service), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(serviceRef))
	accountRef := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(account), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(accountRef))

	passwordBytes := []byte(password)
	passwordRef := C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&passwordBytes[0])), C.CFIndex(len(passwordBytes)))
	defer C.CFRelease(C.CFTypeRef(passwordRef))

	// Create a query dictionary to search for an existing item
	query := C.CFDictionaryCreateMutable(C.kCFAllocatorDefault, 0, &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
	defer C.CFRelease(C.CFTypeRef(query))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassGenericPassword))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrService), unsafe.Pointer(serviceRef))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrAccount), unsafe.Pointer(accountRef))

	// Create a dictionary with the new password to update
	update := C.CFDictionaryCreateMutable(C.kCFAllocatorDefault, 0, &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
	defer C.CFRelease(C.CFTypeRef(update))
	C.CFDictionarySetValue(update, unsafe.Pointer(C.kSecValueData), unsafe.Pointer(passwordRef))

	// Update the item, or add it if it doesn't exist
	var status C.OSStatus
	status = C.SecItemUpdate(C.CFDictionaryRef(query), C.CFDictionaryRef(update))
	if status == C.errSecItemNotFound {
		C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecValueData), unsafe.Pointer(passwordRef))
		status = C.SecItemAdd(C.CFDictionaryRef(query), nil)
	}

	return newKeychainError(status)
}

//nolint:govet // the possible unsafe use is fine here
func getKeychainPassword(service, account string) (string, error) { //nolint:govet
	serviceRef := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(service), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(serviceRef))
	accountRef := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(account), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(accountRef))

	query := C.CFDictionaryCreateMutable(C.kCFAllocatorDefault, 0, &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
	defer C.CFRelease(C.CFTypeRef(query))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassGenericPassword))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrService), unsafe.Pointer(serviceRef))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrAccount), unsafe.Pointer(accountRef))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecReturnData), unsafe.Pointer(C.kCFBooleanTrue))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecMatchLimit), unsafe.Pointer(C.kSecMatchLimitOne))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &result)
	if err := newKeychainError(status); err != nil {
		return "", fmt.Errorf("reading from keychain: %w", err)
	}
	defer C.CFRelease(result)

	length := C.CFDataGetLength(C.CFDataRef(result))
	bytes := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(C.CFDataRef(result))), C.int(length))

	return string(bytes), nil
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
