//go:build linux && cgo
// +build linux,cgo

package cli

/*
#define _GNU_SOURCE
#include <sys/acl.h>
#include <acl/libacl.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Helper to set ACL for file (add user read permission)
int set_user_read_acl(const char *path, uid_t uid) {
	acl_t acl = acl_get_file(path, ACL_TYPE_ACCESS);
	if (!acl) {
		return -1;
	}

	// Create new ACL entry
	acl_entry_t entry;
	if (acl_create_entry(&acl, &entry) < 0) {
		acl_free(acl);
		return -1;
	}

	// Set entry type to user
	if (acl_set_tag_type(entry, ACL_USER) < 0) {
		acl_free(acl);
		return -1;
	}

	// Set the user ID
	if (acl_set_qualifier(entry, &uid) < 0) {
		acl_free(acl);
		return -1;
	}

	// Set read permission
	acl_permset_t permset;
	if (acl_get_permset(entry, &permset) < 0) {
		acl_free(acl);
		return -1;
	}
	if (acl_clear_perms(permset) < 0) {
		acl_free(acl);
		return -1;
	}
	if (acl_add_perm(permset, ACL_READ) < 0) {
		acl_free(acl);
		return -1;
	}

	// Write ACL back
	if (acl_set_file(path, ACL_TYPE_ACCESS, acl) < 0) {
		acl_free(acl);
		return -1;
	}

	acl_free(acl);
	return 0;
}

// Helper to set ACL for directory (add user execute permission for directory traversal)
int set_user_execute_acl(const char *path, uid_t uid) {
	acl_t acl = acl_get_file(path, ACL_TYPE_ACCESS);
	if (!acl) {
		return -1;
	}

	// Create new ACL entry
	acl_entry_t entry;
	if (acl_create_entry(&acl, &entry) < 0) {
		acl_free(acl);
		return -1;
	}

	// Set entry type to user
	if (acl_set_tag_type(entry, ACL_USER) < 0) {
		acl_free(acl);
		return -1;
	}

	// Set the user ID
	if (acl_set_qualifier(entry, &uid) < 0) {
		acl_free(acl);
		return -1;
	}

	// Set execute permission (for directory, this is search)
	acl_permset_t permset;
	if (acl_get_permset(entry, &permset) < 0) {
		acl_free(acl);
		return -1;
	}
	if (acl_clear_perms(permset) < 0) {
		acl_free(acl);
		return -1;
	}
	if (acl_add_perm(permset, ACL_EXECUTE) < 0) {
		acl_free(acl);
		return -1;
	}

	// Write ACL back
	if (acl_set_file(path, ACL_TYPE_ACCESS, acl) < 0) {
		acl_free(acl);
		return -1;
	}

	acl_free(acl);
	return 0;
}
*/
import "C"

import (
	"fmt"
	"os/user"
	"strconv"
	"unsafe"
)

// setPostfixKeyACL sets read permission for the postfix user on the TLS key file.
func setPostfixKeyACL(keyPath string) error {
	// Look up the postfix user
	postfixUser, err := user.Lookup("postfix")
	if err != nil {
		// Postfix user doesn't exist, skip ACL setup
		return nil
	}

	uid, err := strconv.Atoi(postfixUser.Uid)
	if err != nil {
		return fmt.Errorf("parse postfix uid: %w", err)
	}

	// Call C function to set ACL
	cPath := C.CString(keyPath)
	defer C.free(unsafe.Pointer(cPath))

	if C.set_user_read_acl(cPath, C.uid_t(uid)) != 0 {
		return fmt.Errorf("failed to set read ACL for postfix on %s", keyPath)
	}

	return nil
}

// setPostfixDirACL sets execute (search) permission for the postfix user on the directory.
func setPostfixDirACL(dirPath string) error {
	// Look up the postfix user
	postfixUser, err := user.Lookup("postfix")
	if err != nil {
		// Postfix user doesn't exist, skip ACL setup
		return nil
	}

	uid, err := strconv.Atoi(postfixUser.Uid)
	if err != nil {
		return fmt.Errorf("parse postfix uid: %w", err)
	}

	// Call C function to set ACL
	cPath := C.CString(dirPath)
	defer C.free(unsafe.Pointer(cPath))

	if C.set_user_execute_acl(cPath, C.uid_t(uid)) != 0 {
		return fmt.Errorf("failed to set execute ACL for postfix on %s", dirPath)
	}

	return nil
}
