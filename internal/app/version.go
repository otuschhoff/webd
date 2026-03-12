package app

import "fmt"

var (
	Version   = "v0.1.0"
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

func VersionString() string {
	return fmt.Sprintf("%s %s %s", Version, BuildTime, CommitSHA)
}
