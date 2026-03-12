package setup

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"httpsd/internal/app"
)

type passwdEntry struct {
	name string
	uid  int
	gid  int
}

type groupEntry struct {
	name    string
	gid     int
	members []string
}

func Run(opts app.SetupOptions) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("setup must be run as root because it modifies /etc/passwd, /etc/group, file ownership/permissions, Linux file capabilities (setcap), and systemd unit files")
	}

	httpsdGroup, httpsdGroupCreated, err := ensureGroupExists("httpsd", -1)
	if err != nil {
		return err
	}
	if httpsdGroupCreated {
		fmt.Printf("created group httpsd gid=%d\n", httpsdGroup)
	}

	httpsdUID, httpsdPrimaryGID, httpsdUserCreated, err := ensureUserExists("httpsd", httpsdGroup)
	if err != nil {
		return err
	}
	if httpsdUserCreated {
		fmt.Printf("created user httpsd uid=%d gid=%d\n", httpsdUID, httpsdPrimaryGID)
	}

	tlskeyGID, tlskeyCreated, err := ensureGroupExists("tlskey", -1)
	if err != nil {
		return err
	}
	if tlskeyCreated {
		fmt.Printf("created group tlskey gid=%d\n", tlskeyGID)
	}

	membershipChanged, err := ensureUserInGroup("httpsd", "tlskey")
	if err != nil {
		return err
	}
	if membershipChanged {
		fmt.Println("added user httpsd to group tlskey")
	}

	if err := os.Chown(opts.TLSKeyPath, 0, tlskeyGID); err != nil {
		return fmt.Errorf("set owner root:tlskey on %s: %w", opts.TLSKeyPath, err)
	}
	if err := os.Chmod(opts.TLSKeyPath, 0o640); err != nil {
		return fmt.Errorf("set mode 0640 on %s: %w", opts.TLSKeyPath, err)
	}
	fmt.Printf("set TLS key ownership and mode on %s\n", opts.TLSKeyPath)

	if err := os.Chown(opts.TLSCertPath, 0, tlskeyGID); err != nil {
		return fmt.Errorf("set owner root:tlskey on %s: %w", opts.TLSCertPath, err)
	}
	if err := os.Chmod(opts.TLSCertPath, 0o644); err != nil {
		return fmt.Errorf("set mode 0644 on %s: %w", opts.TLSCertPath, err)
	}
	fmt.Printf("set TLS cert ownership and mode on %s\n", opts.TLSCertPath)

	if err := os.MkdirAll("/var/log/httpsd", 0o750); err != nil {
		return fmt.Errorf("create /var/log/httpsd: %w", err)
	}
	if err := os.Chown("/var/log/httpsd", httpsdUID, httpsdGroup); err != nil {
		return fmt.Errorf("chown /var/log/httpsd: %w", err)
	}
	if err := os.Chmod("/var/log/httpsd", 0o750); err != nil {
		return fmt.Errorf("chmod /var/log/httpsd: %w", err)
	}
	fmt.Println("ensured /var/log/httpsd ownership=httpsd:httpsd perms=750")

	installedBinaryPath, err := ensureVersionedInstall()
	if err != nil {
		return err
	}
	if installedBinaryPath != "" {
		fmt.Printf("ensured versioned binary install at %s\n", installedBinaryPath)
	}

	if err := ensureNetBindCapability(opts.BinaryPath); err != nil {
		return err
	}
	fmt.Printf("ensured Linux capability cap_net_bind_service=+ep on %s\n", opts.BinaryPath)

	serviceExists, err := systemdServiceExists("httpsd")
	if err != nil {
		return err
	}
	if !serviceExists {
		if err := os.WriteFile(opts.ServicePath, []byte(app.ServiceUnitContent), 0o644); err != nil {
			return fmt.Errorf("write systemd unit %s: %w", opts.ServicePath, err)
		}
		fmt.Printf("created systemd unit %s\n", opts.ServicePath)
	} else {
		fmt.Println("systemd service httpsd already exists")
	}

	fmt.Println("setup complete")
	fmt.Println("next step: run 'systemctl daemon-reload' if a new unit file was created")
	return nil
}

func ensureVersionedInstall() (string, error) {
	const installRoot = "/opt/httpsd"

	versionDirName, err := buildVersionDirName()
	if err != nil {
		return "", err
	}

	currentExecPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve current executable: %w", err)
	}
	resolvedExecPath, err := filepath.EvalSymlinks(currentExecPath)
	if err == nil {
		currentExecPath = resolvedExecPath
	}

	versionDir := filepath.Join(installRoot, versionDirName)
	versionBinDir := filepath.Join(versionDir, "sbin")
	versionBinaryPath := filepath.Join(versionBinDir, "httpsd")
	currentLink := filepath.Join(installRoot, "current")

	if err := os.MkdirAll(versionBinDir, 0o755); err != nil {
		return "", fmt.Errorf("create versioned binary dir %s: %w", versionBinDir, err)
	}

	if _, err := os.Stat(versionBinaryPath); errors.Is(err, os.ErrNotExist) {
		if err := copyFile(currentExecPath, versionBinaryPath, 0o755); err != nil {
			return "", fmt.Errorf("install binary to %s: %w", versionBinaryPath, err)
		}
	} else if err != nil {
		return "", fmt.Errorf("stat installed binary %s: %w", versionBinaryPath, err)
	}

	newestVersionDir, err := newestInstalledVersionDir(installRoot)
	if err != nil {
		return "", err
	}

	needsLinkUpdate := true
	if target, err := os.Readlink(currentLink); err == nil {
		resolvedTarget := target
		if !filepath.IsAbs(resolvedTarget) {
			resolvedTarget = filepath.Join(installRoot, resolvedTarget)
		}
		resolvedTarget = filepath.Clean(resolvedTarget)
		if resolvedTarget == newestVersionDir {
			needsLinkUpdate = false
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read current symlink %s: %w", currentLink, err)
	}

	if needsLinkUpdate {
		if err := os.Remove(currentLink); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("remove existing current symlink %s: %w", currentLink, err)
		}
		if err := os.Symlink(newestVersionDir, currentLink); err != nil {
			return "", fmt.Errorf("create current symlink %s -> %s: %w", currentLink, newestVersionDir, err)
		}
	}

	return versionBinaryPath, nil
}

func buildVersionDirName() (string, error) {
	baseVersion := strings.TrimSpace(app.Version)
	if baseVersion == "" || baseVersion == "unknown" {
		return "", fmt.Errorf("application version is not set; cannot manage versioned install path")
	}

	buildTimeRaw := strings.TrimSpace(app.BuildTime)
	if buildTimeRaw == "" || buildTimeRaw == "unknown" {
		return "", fmt.Errorf("application build time is not set; cannot manage versioned install path")
	}

	buildTime, err := parseBuildTime(buildTimeRaw)
	if err != nil {
		return "", fmt.Errorf("invalid build time %q: %w", buildTimeRaw, err)
	}

	return fmt.Sprintf("%s-%s", baseVersion, buildTime.UTC().Format("20060102T150405Z")), nil
}

func parseBuildTime(input string) (time.Time, error) {
	if ts, err := time.Parse(time.RFC3339, input); err == nil {
		return ts, nil
	}
	if ts, err := time.Parse("20060102T150405Z", input); err == nil {
		return ts, nil
	}
	return time.Time{}, fmt.Errorf("must be RFC3339 or 20060102T150405Z")
}

func newestInstalledVersionDir(root string) (string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("read install root %s: %w", root, err)
	}

	type versionDir struct {
		name     string
		fullPath string
	}

	versions := make([]versionDir, 0)
	for _, entry := range entries {
		name := entry.Name()
		if name == "current" || !looksLikeVersion(name) {
			continue
		}
		fullPath := filepath.Join(root, name)
		info, err := os.Stat(fullPath)
		if err != nil {
			return "", fmt.Errorf("stat version dir %s: %w", fullPath, err)
		}
		if !info.IsDir() {
			continue
		}
		versions = append(versions, versionDir{name: name, fullPath: fullPath})
	}

	if len(versions) == 0 {
		return "", fmt.Errorf("no version directories found under %s", root)
	}

	sort.Slice(versions, func(i, j int) bool {
		return compareVersionNames(versions[i].name, versions[j].name) > 0
	})

	return versions[0].fullPath, nil
}

func looksLikeVersion(v string) bool {
	_, ok := parseVersionName(v)
	return ok
}

func compareVersionNames(a, b string) int {
	pa, oka := parseVersionName(a)
	pb, okb := parseVersionName(b)
	if !oka || !okb {
		return cmp.Compare(strings.TrimSpace(a), strings.TrimSpace(b))
	}

	maxLen := len(pa.numbers)
	if len(pb.numbers) > maxLen {
		maxLen = len(pb.numbers)
	}
	for i := 0; i < maxLen; i++ {
		av := 0
		if i < len(pa.numbers) {
			av = pa.numbers[i]
		}
		bv := 0
		if i < len(pb.numbers) {
			bv = pb.numbers[i]
		}
		if av != bv {
			return cmp.Compare(av, bv)
		}
	}

	if pa.hasTimestamp && pb.hasTimestamp {
		if cmp := pa.timestamp.Compare(pb.timestamp); cmp != 0 {
			return cmp
		}
	}
	if pa.hasTimestamp && !pb.hasTimestamp {
		return 1
	}
	if !pa.hasTimestamp && pb.hasTimestamp {
		return -1
	}

	return 0
}

type parsedVersionName struct {
	numbers      []int
	timestamp    time.Time
	hasTimestamp bool
}

func parseVersionName(v string) (parsedVersionName, bool) {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "v") || len(v) < 2 {
		return parsedVersionName{}, false
	}

	base := v
	parsed := parsedVersionName{}
	if idx := strings.LastIndex(v, "-"); idx > 1 {
		candidateTS := v[idx+1:]
		if ts, err := time.Parse("20060102T150405Z", candidateTS); err == nil {
			parsed.hasTimestamp = true
			parsed.timestamp = ts
			base = v[:idx]
		}
	}

	parts := strings.Split(strings.TrimPrefix(base, "v"), ".")
	if len(parts) == 0 {
		return parsedVersionName{}, false
	}
	numbers := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return parsedVersionName{}, false
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return parsedVersionName{}, false
		}
		numbers = append(numbers, n)
	}
	parsed.numbers = numbers
	return parsed, true
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func ensureNetBindCapability(binaryPath string) error {
	if strings.TrimSpace(binaryPath) == "" {
		return fmt.Errorf("binary path for setcap cannot be empty")
	}
	if _, err := os.Stat(binaryPath); err != nil {
		return fmt.Errorf("cannot set capability on %s: %w", binaryPath, err)
	}

	if _, err := exec.LookPath("setcap"); err != nil {
		return fmt.Errorf("setcap not found in PATH; install libcap tools to continue")
	}

	cmd := exec.Command("setcap", "cap_net_bind_service=+ep", binaryPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("setcap on %s failed: %v: %s", binaryPath, err, strings.TrimSpace(string(out)))
	}

	if _, err := exec.LookPath("getcap"); err == nil {
		verify := exec.Command("getcap", binaryPath)
		out, err := verify.CombinedOutput()
		if err != nil {
			return fmt.Errorf("getcap verification on %s failed: %v: %s", binaryPath, err, strings.TrimSpace(string(out)))
		}
		capStr := string(out)
		if !strings.Contains(capStr, "cap_net_bind_service") {
			return fmt.Errorf("capability verification failed for %s: %s", binaryPath, strings.TrimSpace(capStr))
		}
	}

	return nil
}

func ensureUserExists(name string, defaultGID int) (uid int, gid int, created bool, err error) {
	entries, err := readPasswdEntries()
	if err != nil {
		return 0, 0, false, err
	}
	for _, e := range entries {
		if e.name == name {
			return e.uid, e.gid, false, nil
		}
	}

	nextUID := nextAvailableUID(entries)
	gid = defaultGID
	line := fmt.Sprintf("%s:x:%d:%d:%s service user:/nonexistent:/usr/sbin/nologin", name, nextUID, gid, name)
	if err := appendLine("/etc/passwd", line); err != nil {
		return 0, 0, false, fmt.Errorf("append /etc/passwd: %w", err)
	}
	return nextUID, gid, true, nil
}

func ensureGroupExists(name string, preferredGID int) (gid int, created bool, err error) {
	entries, lines, err := readGroupEntriesAndLines()
	if err != nil {
		return 0, false, err
	}
	for _, e := range entries {
		if e.name == name {
			return e.gid, false, nil
		}
	}

	gid = preferredGID
	if gid <= 0 || gidInUse(entries, gid) {
		gid = nextAvailableGID(entries)
	}
	lines = append(lines, fmt.Sprintf("%s:x:%d:", name, gid))
	if err := writeLines("/etc/group", lines); err != nil {
		return 0, false, fmt.Errorf("write /etc/group: %w", err)
	}
	return gid, true, nil
}

func ensureUserInGroup(username, groupName string) (bool, error) {
	entries, lines, err := readGroupEntriesAndLines()
	if err != nil {
		return false, err
	}

	lineIndex := -1
	for i, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) != 4 {
			continue
		}
		if parts[0] == groupName {
			lineIndex = i
			break
		}
	}
	if lineIndex == -1 {
		return false, fmt.Errorf("group %s not found in /etc/group", groupName)
	}

	for _, e := range entries {
		if e.name != groupName {
			continue
		}
		for _, member := range e.members {
			if member == username {
				return false, nil
			}
		}
		members := append(e.members, username)
		sort.Strings(members)
		lines[lineIndex] = fmt.Sprintf("%s:x:%d:%s", e.name, e.gid, strings.Join(members, ","))
		if err := writeLines("/etc/group", lines); err != nil {
			return false, fmt.Errorf("write /etc/group: %w", err)
		}
		return true, nil
	}

	return false, fmt.Errorf("group %s parse mismatch", groupName)
}

func systemdServiceExists(name string) (bool, error) {
	paths := []string{
		filepath.Join("/etc/systemd/system", name+".service"),
		filepath.Join("/usr/lib/systemd/system", name+".service"),
		filepath.Join("/lib/systemd/system", name+".service"),
	}
	for _, p := range paths {
		_, err := os.Stat(p)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("stat %s: %w", p, err)
		}
	}
	return false, nil
}

func readPasswdEntries() ([]passwdEntry, error) {
	lines, err := readLines("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("read /etc/passwd: %w", err)
	}

	entries := make([]passwdEntry, 0)
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 7 {
			continue
		}
		uid, uidErr := strconv.Atoi(parts[2])
		gid, gidErr := strconv.Atoi(parts[3])
		if uidErr != nil || gidErr != nil {
			continue
		}
		entries = append(entries, passwdEntry{name: parts[0], uid: uid, gid: gid})
	}
	return entries, nil
}

func readGroupEntriesAndLines() ([]groupEntry, []string, error) {
	lines, err := readLines("/etc/group")
	if err != nil {
		return nil, nil, fmt.Errorf("read /etc/group: %w", err)
	}

	entries := make([]groupEntry, 0)
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 4 {
			continue
		}
		gid, gidErr := strconv.Atoi(parts[2])
		if gidErr != nil {
			continue
		}
		members := make([]string, 0)
		if parts[3] != "" {
			for _, m := range strings.Split(parts[3], ",") {
				m = strings.TrimSpace(m)
				if m != "" {
					members = append(members, m)
				}
			}
		}
		entries = append(entries, groupEntry{name: parts[0], gid: gid, members: members})
	}
	return entries, lines, nil
}

func nextAvailableUID(entries []passwdEntry) int {
	maxUID := 999
	for _, e := range entries {
		if e.uid > maxUID {
			maxUID = e.uid
		}
	}
	return maxUID + 1
}

func gidInUse(entries []groupEntry, gid int) bool {
	for _, e := range entries {
		if e.gid == gid {
			return true
		}
	}
	return false
}

func nextAvailableGID(entries []groupEntry) int {
	maxGID := 999
	for _, e := range entries {
		if e.gid > maxGID {
			maxGID = e.gid
		}
	}
	return maxGID + 1
}

func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return []string{}, nil
	}
	return strings.Split(text, "\n"), nil
}

func writeLines(path string, lines []string) error {
	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0o644)
}
