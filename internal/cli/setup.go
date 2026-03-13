package cli

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

// runSetup prepares the host for httpsd by creating accounts, fixing permissions,
// clearing file capabilities, provisioning config, and updating the systemd unit.
func runSetup(opts app.SetupOptions) error {
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

	if err := ensureNoFileCapabilities(opts.BinaryPath); err != nil {
		return err
	}
	fmt.Printf("ensured no file capabilities are set on %s (systemd AmbientCapabilities handles bind privileges)\n", opts.BinaryPath)

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
		if !entry.IsDir() {
			continue
		}
		versions = append(versions, versionDir{name: name, fullPath: filepath.Join(root, name)})
	}
	if len(versions) == 0 {
		return "", fmt.Errorf("no installed version directories found under %s", root)
	}

	sort.Slice(versions, func(i, j int) bool {
		return cmp.Compare(versions[i].name, versions[j].name) > 0
	})
	return versions[0].fullPath, nil
}

func looksLikeVersion(name string) bool {
	parts := strings.Split(name, "-")
	if len(parts) != 2 {
		return false
	}
	if parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, r := range parts[0] {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	_, err := time.Parse("20060102T150405Z", parts[1])
	return err == nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func ensureNoFileCapabilities(binaryPath string) error {
	if _, err := exec.LookPath("setcap"); err != nil {
		return fmt.Errorf("setcap not found in PATH")
	}
	cmd := exec.Command("setcap", "-r", binaryPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("remove file capabilities on %s failed: %v: %s", binaryPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ensureGroupExists(name string, preferredGID int) (gid int, created bool, err error) {
	groups, err := readGroupFile()
	if err != nil {
		return 0, false, err
	}
	for _, entry := range groups {
		if entry.name == name {
			return entry.gid, false, nil
		}
	}

	gid = preferredGID
	if gid < 0 {
		gid, err = nextAvailableSystemID(groupsToIDs(groups), httpsdMinUID, httpsdMaxUID)
		if err != nil {
			return 0, false, err
		}
	}
	line := fmt.Sprintf("%s:x:%d:\n", name, gid)
	if err := appendUniqueLine("/etc/group", line); err != nil {
		return 0, false, err
	}
	return gid, true, nil
}

func ensureUserExists(name string, primaryGID int) (uid int, gid int, created bool, uidChanged bool, err error) {
	passwd, err := readPasswdFile()
	if err != nil {
		return 0, 0, false, false, err
	}
	for _, entry := range passwd {
		if entry.name != name {
			continue
		}
		if entry.uid >= httpsdMinUID && entry.uid <= httpsdMaxUID {
			return entry.uid, entry.gid, false, false, nil
		}

		newUID, allocErr := nextAvailableSystemID(passwdToUIDs(passwd), httpsdMinUID, httpsdMaxUID)
		if allocErr != nil {
			return 0, 0, false, false, allocErr
		}
		if err := rewritePasswdUID(name, newUID); err != nil {
			return 0, 0, false, false, err
		}
		return newUID, entry.gid, false, true, nil
	}

	uid, err = nextAvailableSystemID(passwdToUIDs(passwd), httpsdMinUID, httpsdMaxUID)
	if err != nil {
		return 0, 0, false, false, err
	}
	line := fmt.Sprintf("%s:x:%d:%d::/nonexistent:/usr/sbin/nologin\n", name, uid, primaryGID)
	if err := appendUniqueLine("/etc/passwd", line); err != nil {
		return 0, 0, false, false, err
	}
	return uid, primaryGID, true, false, nil
}

func ensureUserInGroup(userName, groupName string) (bool, error) {
	groups, err := readGroupFile()
	if err != nil {
		return false, err
	}

	updated := false
	for i := range groups {
		if groups[i].name != groupName {
			continue
		}
		for _, member := range groups[i].members {
			if member == userName {
				return false, nil
			}
		}
		groups[i].members = append(groups[i].members, userName)
		sort.Strings(groups[i].members)
		updated = true
		break
	}
	if !updated {
		return false, fmt.Errorf("group %s not found", groupName)
	}

	if err := writeGroupFile(groups); err != nil {
		return false, err
	}
	return true, nil
}

func validateServiceIdentity(userName, primaryGroupName, tlsGroupName string) error {
	u, err := user.Lookup(userName)
	if err != nil {
		return fmt.Errorf("lookup service user %s: %w", userName, err)
	}
	if u.Username != userName {
		return fmt.Errorf("service user lookup returned unexpected username %q", u.Username)
	}
	if u.Gid == "" {
		return fmt.Errorf("service user %s has empty primary gid", userName)
	}

	g, err := user.LookupGroup(primaryGroupName)
	if err != nil {
		return fmt.Errorf("lookup primary group %s: %w", primaryGroupName, err)
	}
	if u.Gid != g.Gid {
		return fmt.Errorf("service user %s primary gid=%s does not match group %s gid=%s", userName, u.Gid, primaryGroupName, g.Gid)
	}

	groupIDs, err := u.GroupIds()
	if err != nil {
		return fmt.Errorf("lookup service user %s supplementary groups: %w", userName, err)
	}
	tlsGroup, err := user.LookupGroup(tlsGroupName)
	if err != nil {
		return fmt.Errorf("lookup tls group %s: %w", tlsGroupName, err)
	}
	for _, groupID := range groupIDs {
		if groupID == tlsGroup.Gid {
			return nil
		}
	}
	return fmt.Errorf("service user %s is not a member of group %s (gid=%s)", userName, tlsGroupName, tlsGroup.Gid)
}

func validateAccountDatabases(userName, tlsGroupName string) error {
	passwd, err := readPasswdFile()
	if err != nil {
		return err
	}
	groups, err := readGroupFile()
	if err != nil {
		return err
	}

	var userEntry *passwdEntry
	for i := range passwd {
		if passwd[i].name == userName {
			userEntry = &passwd[i]
			break
		}
	}
	if userEntry == nil {
		return fmt.Errorf("user %s missing from /etc/passwd", userName)
	}
	if userEntry.uid < httpsdMinUID || userEntry.uid > httpsdMaxUID {
		return fmt.Errorf("user %s has uid %d outside allowed range %d-%d", userName, userEntry.uid, httpsdMinUID, httpsdMaxUID)
	}

	primaryGroupOK := false
	tlsGroupOK := false
	for _, entry := range groups {
		if entry.name == userName && entry.gid == userEntry.gid {
			primaryGroupOK = true
		}
		if entry.name == tlsGroupName {
			for _, member := range entry.members {
				if member == userName {
					tlsGroupOK = true
					break
				}
			}
		}
	}
	if !primaryGroupOK {
		return fmt.Errorf("primary group %s missing or gid mismatch for user %s", userName, userName)
	}
	if !tlsGroupOK {
		return fmt.Errorf("group %s does not list user %s as a member", tlsGroupName, userName)
	}
	return nil
}

func readPasswdFile() ([]passwdEntry, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("read /etc/passwd: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	entries := make([]passwdEntry, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(parts[3])
		if err != nil {
			continue
		}
		entries = append(entries, passwdEntry{name: parts[0], uid: uid, gid: gid})
	}
	return entries, nil
}

func readGroupFile() ([]groupEntry, error) {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil, fmt.Errorf("read /etc/group: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	entries := make([]groupEntry, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		gid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		members := []string{}
		if parts[3] != "" {
			members = strings.Split(parts[3], ",")
		}
		entries = append(entries, groupEntry{name: parts[0], gid: gid, members: members})
	}
	return entries, nil
}

func writeGroupFile(entries []groupEntry) error {
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		lines = append(lines, fmt.Sprintf("%s:x:%d:%s", entry.name, entry.gid, strings.Join(entry.members, ",")))
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile("/etc/group", []byte(content), 0o644); err != nil {
		return fmt.Errorf("write /etc/group: %w", err)
	}
	return nil
}

func appendUniqueLine(path, line string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if strings.Contains(string(data), line) {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s for append: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("append %s: %w", path, err)
	}
	return nil
}

func rewritePasswdUID(userName string, newUID int) error {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return fmt.Errorf("read /etc/passwd: %w", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	updated := false
	for i, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) != 7 || parts[0] != userName {
			continue
		}
		parts[2] = strconv.Itoa(newUID)
		lines[i] = strings.Join(parts, ":")
		updated = true
		break
	}
	if !updated {
		return fmt.Errorf("user %s not found in /etc/passwd", userName)
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile("/etc/passwd", []byte(content), 0o644); err != nil {
		return fmt.Errorf("write /etc/passwd: %w", err)
	}
	return nil
}

func passwdToUIDs(entries []passwdEntry) map[int]struct{} {
	ids := make(map[int]struct{}, len(entries))
	for _, entry := range entries {
		ids[entry.uid] = struct{}{}
	}
	return ids
}

func groupsToIDs(entries []groupEntry) map[int]struct{} {
	ids := make(map[int]struct{}, len(entries))
	for _, entry := range entries {
		ids[entry.gid] = struct{}{}
	}
	return ids
}

func nextAvailableSystemID(used map[int]struct{}, minID, maxID int) (int, error) {
	for candidate := minID; candidate <= maxID; candidate++ {
		if _, exists := used[candidate]; !exists {
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("no available system id in range %d-%d", minID, maxID)
}
