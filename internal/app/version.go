package app

import "fmt"

// Version, BuildTime, and CommitSHA are build metadata values populated at link time.
var (
	Version   = "v0.1.0"
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

// VersionString returns the formatted version banner shown by the CLI.
func VersionString() string {
	return fmt.Sprintf("%s %s %s", Version, BuildTime, CommitSHA)
}
