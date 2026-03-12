package setup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

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
