//go:build darwin && cgo

package clitoken

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

CFStringRef GoStringToCFStringRef(const char *str) {
	return CFStringCreateWithCString(kCFAllocatorDefault, str, kCFStringEncodingUTF8);
}

int set_keychain_password(const char *service, const char *account, const char *password) {
	CFStringRef serviceRef = GoStringToCFStringRef(service);
	CFStringRef accountRef = GoStringToCFStringRef(account);
	CFDataRef passwordRef = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)password, strlen(password));

	// Create a query dictionary to search for an existing item
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, serviceRef);
	CFDictionarySetValue(query, kSecAttrAccount, accountRef);

	// Create a dictionary with the new password to update
	CFMutableDictionaryRef update = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(update, kSecValueData, passwordRef);

	OSStatus status = SecItemUpdate(query, update);
	if (status == errSecItemNotFound) {
		CFDictionarySetValue(query, kSecValueData, passwordRef);
		status = SecItemAdd(query, NULL);
	}

	CFRelease(query);
	CFRelease(update);
	CFRelease(serviceRef);
	CFRelease(accountRef);
	CFRelease(passwordRef);

	return status;
}

int get_keychain_password(const char *service, const char *account, char **password) {
	CFStringRef serviceRef = GoStringToCFStringRef(service);
	CFStringRef accountRef = GoStringToCFStringRef(account);

	CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, serviceRef);
	CFDictionarySetValue(query, kSecAttrAccount, accountRef);
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

	CFDataRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&result);

	if (status == errSecSuccess) {
		long length = CFDataGetLength(result);
		*password = (char *)malloc(length + 1);
		if (*password == NULL) {
			abort();
		}
		memcpy(*password, CFDataGetBytePtr(result), length);
		(*password)[length] = '\0';
		CFRelease(result);
	}

	CFRelease(query);
	CFRelease(serviceRef);
	CFRelease(accountRef);

	return status;
}
*/
import "C"
import (
	"encoding/json"
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
		return C.GoString(C.CFStringGetCStringPtr(cfError, C.kCFStringEncodingUTF8))
	}
	return fmt.Sprintf("Unknown keychain error: %d", e.status)
}

func newKeychainError(status C.OSStatus) error {
	if status == C.errSecSuccess {
		return nil
	}
	return &keychainError{status: status}
}

type KeychainCredentialCache struct{}

var _ tokencache.CredentialCache = &KeychainCredentialCache{}

func (k *KeychainCredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	service := C.CString(issuer)
	account := C.CString(key)
	var result *C.char
	status := C.get_keychain_password(service, account, &result)
	C.free(unsafe.Pointer(service))
	C.free(unsafe.Pointer(account))

	if status == C.errSecItemNotFound { // no pw found
		return nil, nil
	} else if err := newKeychainError(status); err != nil {
		return nil, fmt.Errorf("reading password from keychain: %w", err)
	}

	password := C.GoString(result)
	C.free(unsafe.Pointer(result))

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

	service := C.CString(issuer)
	account := C.CString(key)
	password := C.CString(string(b))
	status := C.set_keychain_password(service, account, password)
	C.free(unsafe.Pointer(service))
	C.free(unsafe.Pointer(account))
	C.free(unsafe.Pointer(password))

	if err := newKeychainError(status); err != nil {
		return fmt.Errorf("setting password: %w", err)
	}

	return nil
}

func (k *KeychainCredentialCache) Available() bool {
	// should always be this, but check anyway
	return runtime.GOOS == "darwin"
}
