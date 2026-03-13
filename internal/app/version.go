package app

import "fmt"

const Version = "v0.1.1"

// BuildTime and CommitSHA are build metadata values populated at link time.
var (
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

// VersionString returns the formatted version banner shown by the CLI.
func VersionString() string {
	return fmt.Sprintf("%s %s %s", Version, BuildTime, CommitSHA)
}
