package app

import (
	"fmt"
	"strings"
	"time"
)

const Version = "v0.1.1"

// BuildTime and CommitSHA are build metadata values populated at link time.
var (
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

// VersionString returns the formatted version string:
//
//	<Version>-<YYYYMMDD>-<hhmmss>.<commitSha>
//
// Falls back to the bare Version constant if build metadata is unavailable.
func VersionString() string {
	bt := strings.TrimSpace(BuildTime)
	cs := strings.TrimSpace(CommitSHA)
	if bt == "" || bt == "unknown" || cs == "" || cs == "unknown" {
		return Version
	}
	if len(cs) > 7 {
		cs = cs[:7]
	}

	var t time.Time
	for _, layout := range []string{time.RFC3339, "20060102T150405Z"} {
		if parsed, err := time.Parse(layout, bt); err == nil {
			t = parsed.UTC()
			break
		}
	}
	if t.IsZero() {
		return Version
	}

	return fmt.Sprintf("%s-%s-%s.%s", Version, t.Format("20060102"), t.Format("150405"), cs)
}
