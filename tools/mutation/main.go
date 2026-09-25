// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

// Command mutation answers the house question for every gate: how do we know
// it can fail? Each entry in mutations.json removes one rule of the signer.
// The mutant must COMPILE - a build error proves nothing - and its named test
// must go RED. The command exits non-zero if any mutant survives or does not
// build. Run from the repository root: go run ./tools/mutation
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type mutation struct {
	Check string `json:"check"`
	File  string `json:"file"`
	Test  string `json:"test"`
	// Pkg is the package whose test judges the mutant, when it is not the
	// mutated file's own (a controller test catching an issuer bug).
	Pkg  string `json:"pkg,omitempty"`
	From string `json:"from"`
	To   string `json:"to"`
}

func main() {
	raw, err := os.ReadFile("tools/mutation/mutations.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var ms []mutation
	if err := json.Unmarshal(raw, &ms); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	failed := false
	for _, m := range ms {
		verdict, err := run(m)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR  %s: %v\n", m.Check, err)
			failed = true
			continue
		}
		fmt.Printf("%-6s %s\n", verdict, m.Check)
		if verdict != "KILLED" {
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

// run applies one mutation, judges it, and always restores the file.
func run(m mutation) (string, error) {
	orig, err := os.ReadFile(m.File)
	if err != nil {
		return "", err
	}
	if n := strings.Count(string(orig), m.From); n != 1 {
		return "", fmt.Errorf("anchor found %d times, want exactly once", n)
	}
	if err := os.WriteFile(m.File, []byte(strings.Replace(string(orig), m.From, m.To, 1)), 0o644); err != nil {
		return "", err
	}
	defer os.WriteFile(m.File, orig, 0o644)

	pkg := "./" + filepath.Dir(m.File)
	if exec.Command("go", "vet", pkg).Run() != nil {
		return "BUILD", nil // the mutant does not compile: it proves nothing
	}
	if m.Pkg != "" {
		pkg = m.Pkg
	}
	if exec.Command("go", "vet", pkg).Run() != nil {
		return "BUILD", nil // the mutant does not compile: it proves nothing
	}
	if exec.Command("go", "test", pkg, "-run", "^"+m.Test+"$", "-count=1").Run() == nil {
		return "ALIVE", nil // the test stayed green without its rule
	}
	return "KILLED", nil
}
