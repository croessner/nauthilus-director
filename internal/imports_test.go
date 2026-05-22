package internal_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestProductionPackagesDoNotImportPOC(t *testing.T) {
	command := exec.Command("go", "list", "-mod=vendor", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", "./...")
	command.Dir = ".."

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		t.Fatalf("go list failed: %v\n%s", err, stderr.String())
	}

	for line := range strings.SplitSeq(strings.TrimSpace(stdout.String()), "\n") {
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		importPath := fields[0]

		if strings.Contains(importPath, "/poc") {
			t.Fatalf("production module includes POC package %q", importPath)
		}

		for _, imported := range fields[1:] {
			if strings.Contains(imported, "/poc") {
				t.Fatalf("production package %q imports POC package %q", importPath, imported)
			}
		}
	}
}
