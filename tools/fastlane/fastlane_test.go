// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

package fastlane

import (
	"errors"
	"os"
	"testing"
)

// The fixtures stand for the three states of the chain. `fires` is the
// intended one; the other two are how the fast lane was lost or would be.
func TestFixtures(t *testing.T) {
	for _, tc := range []struct {
		file string
		want error
	}{
		{"testdata/fires.yml", nil},
		{"testdata/fires-block-needs.yml", nil},
		{"testdata/trigger-off.yml", ErrTriggerOff},
		{"testdata/trigger-false.yml", ErrTriggerOff},
		{"testdata/tag-before-publish.yml", ErrTagBeforePublish},
	} {
		raw, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		if got := Check(string(raw)); !errors.Is(got, tc.want) {
			t.Errorf("%s: Check = %v, want %v", tc.file, got, tc.want)
		}
	}
}

// The repository's own pipeline: a release must start the fast lane, and
// only after the package is published.
func TestRepositoryCI(t *testing.T) {
	raw, err := os.ReadFile("../../.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(string(raw)); err != nil {
		t.Fatal(err)
	}
}
