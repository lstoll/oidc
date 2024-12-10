//go:build darwin && cgo

package clitoken

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"unsafe"

	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/tokencache"
	"golang.org/x/oauth2"
)

func init() {
	platformCaches = append(platformCaches, &KeychainCredentialCache{})
}

// procSum is the sha256 of the running binary. This lets us track in the
// keychain which actual binary created the item, so we can avoid all the "enter
// password to access" prompts.
//
// this is not super fast - about 5ms on a m1 pro for the test binary. In future
// it would be nice to find an alternative to pin an executable to something
// else, preferable the keychain entry.
//
// or, i wonder if the create time of the binary is good enough?
var procSum = func() []byte {
	info, _ := debug.ReadBuildInfo()
	log.Printf("info: %#v", info)

	execPath, err := os.Executable()
	if err != nil {
		panic("getting executable path: " + err.Error())
	}

	// Open the executable file
	file, err := os.Open(execPath)
	if err != nil {
		panic("opening executable: " + err.Error())

	}
	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		panic("calculating shasum: " + err.Error())
	}

	return hash.Sum(nil)
}()

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

	// TODO - add the binary name in somehow, to make different bins
	// for the same service not clash on keys. Prefix the issuer probably?

	// if err := deleteKeychainPassword(issuer, key); err != nil {
	// 	return fmt.Errorf("deleting: %w", err)
	// }

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

	procSumRef := C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&procSum[0])), C.CFIndex(len(procSum)))
	defer C.CFRelease(C.CFTypeRef(procSumRef))

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
		// TODO - kSecAttrLabel
		C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecValueData), unsafe.Pointer(passwordRef))
		C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecAttrGeneric), unsafe.Pointer(procSumRef))
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

	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecReturnAttributes), unsafe.Pointer(C.kCFBooleanTrue))

	C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecMatchLimit), unsafe.Pointer(C.kSecMatchLimitOne))
	// C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecUseNoAuthenticationUI), unsafe.Pointer(C.kCFBooleanTrue))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &result)
	if err := newKeychainError(status); err != nil {
		return "", fmt.Errorf("reading from keychain: %w", err)
	}
	defer C.CFRelease(result)

	count := C.CFDictionaryGetCount(C.CFDictionaryRef(result))
	log.Printf("attr count: %d", count)

	if count > 0 {
		m := map[C.CFTypeRef]C.CFTypeRef{}
		keys := make([]C.CFTypeRef, count)
		values := make([]C.CFTypeRef, count)
		C.CFDictionaryGetKeysAndValues(C.CFDictionaryRef(result), (*unsafe.Pointer)(unsafe.Pointer(&keys[0])), (*unsafe.Pointer)(unsafe.Pointer(&values[0])))
		m = make(map[C.CFTypeRef]C.CFTypeRef, count)
		for i := C.CFIndex(0); i < count; i++ {
			m[keys[i]] = values[i]
		}

		for k, v := range m {
			_ = v
			ks := cfStringToString(C.CFStringRef(k))
			log.Printf("k: %s", ks)
			switch k {
			case C.CFTypeRef(C.kSecAttrLabel):
				log.Printf("label: %s", cfStringToString(C.CFStringRef(v)))
			case C.CFTypeRef(C.kSecAttrService):
				log.Printf("service: %s", cfStringToString(C.CFStringRef(v)))
			case C.CFTypeRef(C.kSecAttrAccount):
				log.Printf("account: %s", cfStringToString(C.CFStringRef(v)))
			case C.CFTypeRef(C.kSecClass):
				log.Printf("class: %s", cfStringToString(C.CFStringRef(v)))
			case C.CFTypeRef(C.kSecAttrGeneric):
				length := C.CFDataGetLength(C.CFDataRef(v))
				bytes := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(C.CFDataRef(v))), C.int(length))
				log.Printf("shasum: %x", bytes)
			}
		}
	}

	// check if the shasum matches here. if it does, add return data and do the get.
	// if not, return a not found error. we can set it later.

	// C.CFDictionarySetValue(query, unsafe.Pointer(C.kSecReturnData), unsafe.Pointer(C.kCFBooleanTrue))

	return "", nil

	length := C.CFDataGetLength(C.CFDataRef(result))
	bytes := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(C.CFDataRef(result))), C.int(length))

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

	// Update the item, or add it if it doesn't exist
	var status C.OSStatus
	status = C.SecItemDelete(C.CFDictionaryRef(query))
	if status == C.errSecItemNotFound {
		return nil
	}

	return newKeychainError(status)
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
