package cli

import (
	"strings"
	"testing"
)

func TestBuildLetsEncryptTimerUnitUsesDailyCalendar(t *testing.T) {
	unit := buildLetsEncryptTimerUnit(86400)

	if strings.Contains(unit, "OnBootSec=10m") {
		t.Fatalf("expected timer unit to drop OnBootSec, got:\n%s", unit)
	}
	if strings.Contains(unit, "OnUnitActiveSec") {
		t.Fatalf("expected timer unit to drop OnUnitActiveSec, got:\n%s", unit)
	}
	if !strings.Contains(unit, "OnCalendar=daily") {
		t.Fatalf("expected timer unit to include OnCalendar=daily, got:\n%s", unit)
	}
}
