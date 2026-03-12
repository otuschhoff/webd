package reloadcmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Run locates running httpsd processes and sends them SIGHUP for in-place reload.
func Run() error {
	pids, err := findHTTPSDPIDs()
	if err != nil {
		return err
	}
	if len(pids) == 0 {
		return fmt.Errorf("no running httpsd process found")
	}

	sent := 0
	for _, pid := range pids {
		if killErr := syscall.Kill(pid, syscall.SIGHUP); killErr != nil {
			log.Printf("reload failed pid=%d err=%v", pid, killErr)
			continue
		}
		sent++
		fmt.Printf("sent SIGHUP to pid=%d\n", pid)
	}

	if sent == 0 {
		return fmt.Errorf("could not signal any running httpsd process")
	}
	return nil
}

func findHTTPSDPIDs() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	self := os.Getpid()
	pids := make([]int, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, convErr := strconv.Atoi(entry.Name())
		if convErr != nil || pid == self {
			continue
		}

		comm, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if readErr != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == "httpsd" {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}
