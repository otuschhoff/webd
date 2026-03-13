package setup

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"httpsd/internal/app"
)

const defaultConfigYAML = `# Routes are matched by longest path_prefix first.
routes:
  - path_prefix: /api/
    upstream: http://127.0.0.1:8080/api/v1/

  # Fallback route for all other traffic.
  - path_prefix: /
    upstream: http://127.0.0.1:3000
`

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

const (
	httpsdMinUID = 500
	httpsdMaxUID = 999
)

// Run prepares the host for httpsd by creating accounts, fixing permissions,
// installing capabilities, provisioning config, and updating the systemd unit.
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

	httpsdUID, httpsdPrimaryGID, httpsdUserCreated, httpsdUIDChanged, err := ensureUserExists("httpsd", httpsdGroup)
	if err != nil {
		return err
	}
	if httpsdUserCreated {
		fmt.Printf("created user httpsd uid=%d gid=%d\n", httpsdUID, httpsdPrimaryGID)
	}
	if httpsdUIDChanged {
		fmt.Printf("updated user httpsd uid=%d gid=%d to enforce allowed uid range %d-%d\n", httpsdUID, httpsdPrimaryGID, httpsdMinUID, httpsdMaxUID)
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

	if err := validateServiceIdentity("httpsd", "httpsd", "tlskey"); err != nil {
		return err
	}
	if err := validateAccountDatabases("httpsd", "tlskey"); err != nil {
		return err
	}

	if _, err := os.Stat(opts.TLSKeyPath); err != nil {
		return fmt.Errorf("verify TLS key %s: %w", opts.TLSKeyPath, err)
	}
	if _, err := os.Stat(opts.TLSCertPath); err != nil {
		return fmt.Errorf("verify TLS cert %s: %w", opts.TLSCertPath, err)
	}
	fmt.Printf("verified TLS cert/key paths exist without changing ownership/perms cert=%s key=%s\n", opts.TLSCertPath, opts.TLSKeyPath)

	if err := ensureEtcConfig(httpsdGroup); err != nil {
		return err
	}

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

	serviceChanged, err := ensureSystemdUnit(opts.ServicePath, app.ServiceUnitContent, opts.Force)
	if err != nil {
		return err
	}
	if serviceChanged {
		fmt.Printf("updated systemd unit %s\n", opts.ServicePath)
		if err := daemonReload(); err != nil {
			return err
		}
		fmt.Println("systemd daemon-reload completed")
	} else {
		fmt.Println("systemd service file is already up-to-date")
	}

	fmt.Println("setup complete")
	return nil
}

func ensureEtcConfig(httpsdGroup int) error {
	const etcDir = "/etc/httpsd"
	const configPath = app.DefaultConfigPath

	if err := os.MkdirAll(etcDir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", etcDir, err)
	}
	if err := os.Chown(etcDir, 0, httpsdGroup); err != nil {
		return fmt.Errorf("chown %s to root:httpsd: %w", etcDir, err)
	}
	if err := os.Chmod(etcDir, 0o750); err != nil {
		return fmt.Errorf("chmod %s to 0750: %w", etcDir, err)
	}
	fmt.Println("ensured /etc/httpsd ownership=root:httpsd perms=750")

	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(configPath, []byte(defaultConfigYAML), 0o640); err != nil {
			return fmt.Errorf("write default config %s: %w", configPath, err)
		}
		if err := os.Chown(configPath, 0, httpsdGroup); err != nil {
			return fmt.Errorf("chown %s to root:httpsd: %w", configPath, err)
		}
		fmt.Printf("deployed config example to %s\n", configPath)
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", configPath, err)
	} else {
		fmt.Printf("config file already exists: %s\n", configPath)
	}

	return nil
}

func ensureSystemdUnit(path, desired string, force bool) (bool, error) {
	existing, err := os.ReadFile(path)
	if err == nil {
		if string(existing) == desired {
			if !force {
				return false, nil
			}
		}
		if string(existing) != desired && !force {
			return false, fmt.Errorf("systemd unit %s differs from required defaults; rerun setup with --force to overwrite it", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("read systemd unit %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("create systemd dir for %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(desired), 0o644); err != nil {
		return false, fmt.Errorf("write systemd unit %s: %w", path, err)
	}
	return true, nil
}

func daemonReload() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found in PATH; cannot run daemon-reload")
	}
	cmd := exec.Command("systemctl", "daemon-reload")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
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
	baseVersion = strings.TrimPrefix(baseVersion, "v")
	if baseVersion == "" {
		return "", fmt.Errorf("application version %q is invalid for install path", app.Version)
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
	if v == "" {
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

	base = strings.TrimPrefix(base, "v")
	parts := strings.Split(base, ".")
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

func ensureUserExists(name string, defaultGID int) (uid int, gid int, created bool, uidChanged bool, err error) {
	entries, lines, err := readPasswdEntriesAndLines()
	if err != nil {
		return 0, 0, false, false, err
	}
	for _, e := range entries {
		if e.name == name {
			if uidWithinRange(e.uid, httpsdMinUID, httpsdMaxUID) {
				return e.uid, e.gid, false, false, nil
			}
			nextUID, rangeErr := nextAvailableUID(entries, httpsdMinUID, httpsdMaxUID)
			if rangeErr != nil {
				return 0, 0, false, false, fmt.Errorf("select replacement uid for %s: %w", name, rangeErr)
			}
			if err := rewritePasswdUID(lines, name, nextUID); err != nil {
				return 0, 0, false, false, fmt.Errorf("rewrite /etc/passwd uid for %s: %w", name, err)
			}
			return nextUID, e.gid, false, true, nil
		}
	}

	nextUID, err := nextAvailableUID(entries, httpsdMinUID, httpsdMaxUID)
	if err != nil {
		return 0, 0, false, false, fmt.Errorf("select uid for %s: %w", name, err)
	}
	gid = defaultGID
	line := fmt.Sprintf("%s:x:%d:%d:%s service user:/nonexistent:/usr/sbin/nologin", name, nextUID, gid, name)
	if err := appendLine("/etc/passwd", line); err != nil {
		return 0, 0, false, false, fmt.Errorf("append /etc/passwd: %w", err)
	}
	return nextUID, gid, true, false, nil
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

func validateServiceIdentity(username, primaryGroup, auxGroup string) error {
	passwdLine, err := runGetent("passwd", username)
	if err != nil {
		return fmt.Errorf("service user validation failed: getent passwd %s: %w (run setup again and validate /etc/passwd with pwck)", username, err)
	}
	passParts := strings.Split(passwdLine, ":")
	if len(passParts) != 7 {
		return fmt.Errorf("service user validation failed: malformed passwd entry for %s: %q", username, passwdLine)
	}

	primaryGroupLine, err := runGetent("group", primaryGroup)
	if err != nil {
		return fmt.Errorf("service group validation failed: getent group %s: %w (validate /etc/group with grpck)", primaryGroup, err)
	}
	primaryGroupParts := strings.Split(primaryGroupLine, ":")
	if len(primaryGroupParts) != 4 {
		return fmt.Errorf("service group validation failed: malformed group entry for %s: %q", primaryGroup, primaryGroupLine)
	}

	if passParts[3] != primaryGroupParts[2] {
		return fmt.Errorf("service identity mismatch: user %s has gid %s but group %s has gid %s", username, passParts[3], primaryGroup, primaryGroupParts[2])
	}

	auxGroupLine, err := runGetent("group", auxGroup)
	if err != nil {
		return fmt.Errorf("auxiliary group validation failed: getent group %s: %w", auxGroup, err)
	}
	auxParts := strings.Split(auxGroupLine, ":")
	if len(auxParts) != 4 {
		return fmt.Errorf("auxiliary group validation failed: malformed group entry for %s: %q", auxGroup, auxGroupLine)
	}
	members := map[string]struct{}{}
	if auxParts[3] != "" {
		for _, m := range strings.Split(auxParts[3], ",") {
			members[strings.TrimSpace(m)] = struct{}{}
		}
	}
	if _, ok := members[username]; !ok {
		return fmt.Errorf("auxiliary group validation failed: user %s is not listed in %s", username, auxGroup)
	}

	if _, err := user.Lookup(username); err != nil {
		return fmt.Errorf("nss lookup failed for user %s: %w", username, err)
	}
	if _, err := user.LookupGroup(primaryGroup); err != nil {
		return fmt.Errorf("nss lookup failed for group %s: %w", primaryGroup, err)
	}
	if _, err := user.LookupGroup(auxGroup); err != nil {
		return fmt.Errorf("nss lookup failed for group %s: %w", auxGroup, err)
	}

	fmt.Printf("validated service identity user=%s primary_group=%s auxiliary_group=%s\n", username, primaryGroup, auxGroup)
	return nil
}

func runGetent(database, key string) (string, error) {
	if _, err := exec.LookPath("getent"); err != nil {
		return "", fmt.Errorf("getent not found in PATH")
	}
	cmd := exec.Command("getent", database, key)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return "", fmt.Errorf("no entry returned")
	}
	firstLine := strings.Split(line, "\n")[0]
	return firstLine, nil
}

func validateAccountDatabases(requiredGroups ...string) error {
	passwdEntries, err := readPasswdEntries()
	if err != nil {
		return fmt.Errorf("account database validation failed: %w", err)
	}
	groupEntries, _, err := readGroupEntriesAndLines()
	if err != nil {
		return fmt.Errorf("group database validation failed: %w", err)
	}

	userNameCount := map[string]int{}
	userIDCount := map[int]int{}
	for _, e := range passwdEntries {
		userNameCount[e.name]++
		userIDCount[e.uid]++
	}
	if userNameCount["httpsd"] != 1 {
		return fmt.Errorf("account database validation failed: expected exactly one httpsd user entry in /etc/passwd, found %d", userNameCount["httpsd"])
	}
	httpsdUID := -1
	httpsdGID := -1
	for _, e := range passwdEntries {
		if e.name == "httpsd" {
			httpsdUID = e.uid
			httpsdGID = e.gid
			break
		}
	}
	if httpsdUID < 0 || httpsdGID < 0 {
		return fmt.Errorf("account database validation failed: could not resolve httpsd uid/gid from /etc/passwd")
	}
	if userIDCount[httpsdUID] != 1 {
		return fmt.Errorf("account database validation failed: uid %d is not unique in /etc/passwd", httpsdUID)
	}

	groupNameCount := map[string]int{}
	groupIDCount := map[int]int{}
	for _, e := range groupEntries {
		groupNameCount[e.name]++
		groupIDCount[e.gid]++
	}
	if groupNameCount["httpsd"] != 1 {
		return fmt.Errorf("group database validation failed: expected exactly one httpsd group entry in /etc/group, found %d", groupNameCount["httpsd"])
	}
	for _, g := range requiredGroups {
		if groupNameCount[g] != 1 {
			return fmt.Errorf("group database validation failed: expected exactly one %s group entry in /etc/group, found %d", g, groupNameCount[g])
		}
	}
	httpsdPrimaryGroupGID := -1
	for _, e := range groupEntries {
		if e.name == "httpsd" {
			httpsdPrimaryGroupGID = e.gid
			break
		}
	}
	if httpsdPrimaryGroupGID < 0 {
		return fmt.Errorf("group database validation failed: could not resolve httpsd group gid from /etc/group")
	}
	if groupIDCount[httpsdPrimaryGroupGID] != 1 {
		return fmt.Errorf("group database validation failed: gid %d is not unique in /etc/group", httpsdPrimaryGroupGID)
	}
	if httpsdGID != httpsdPrimaryGroupGID {
		return fmt.Errorf("account/group mismatch: httpsd user gid=%d but httpsd group gid=%d", httpsdGID, httpsdPrimaryGroupGID)
	}

	if err := runReadonlyAccountChecker("pwck", "-r"); err != nil {
		fmt.Printf("warning: pwck consistency warnings ignored: %v\n", err)
	}
	if err := runReadonlyAccountChecker("grpck", "-r"); err != nil {
		fmt.Printf("warning: grpck consistency warnings ignored: %v\n", err)
	}

	fmt.Println("validated account database consistency (duplicates/mismatch checks + best-effort pwck/grpck)")
	return nil
}

func runReadonlyAccountChecker(tool string, args ...string) error {
	if _, err := exec.LookPath(tool); err != nil {
		return fmt.Errorf("%s not found in PATH", tool)
	}
	cmd := exec.Command(tool, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func readPasswdEntries() ([]passwdEntry, error) {
	entries, _, err := readPasswdEntriesAndLines()
	return entries, err
}

func readPasswdEntriesAndLines() ([]passwdEntry, []string, error) {
	lines, err := readLines("/etc/passwd")
	if err != nil {
		return nil, nil, fmt.Errorf("read /etc/passwd: %w", err)
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
	return entries, lines, nil
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

func nextAvailableUID(entries []passwdEntry, minUID, maxUID int) (int, error) {
	used := make(map[int]struct{}, len(entries))
	for _, e := range entries {
		used[e.uid] = struct{}{}
	}
	for uid := minUID; uid <= maxUID; uid++ {
		if _, ok := used[uid]; !ok {
			return uid, nil
		}
	}
	return 0, fmt.Errorf("no available uid in range %d-%d", minUID, maxUID)
}

func uidWithinRange(uid, minUID, maxUID int) bool {
	return uid >= minUID && uid <= maxUID
}

func rewritePasswdUID(lines []string, username string, newUID int) error {
	for i, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) != 7 {
			continue
		}
		if parts[0] == username {
			parts[2] = strconv.Itoa(newUID)
			lines[i] = strings.Join(parts, ":")
			return writeLines("/etc/passwd", lines)
		}
	}
	return fmt.Errorf("user %s not found", username)
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
