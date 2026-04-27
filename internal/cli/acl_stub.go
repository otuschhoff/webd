// +build !linux

package cli


// setPostfixKeyACL is a no-op on non-Linux systems
func setPostfixKeyACL(keyPath string) error {
	return nil
}

// setPostfixDirACL is a no-op on non-Linux systems
func setPostfixDirACL(dirPath string) error {
	return nil
}
