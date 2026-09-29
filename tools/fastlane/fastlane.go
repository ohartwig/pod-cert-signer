// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

// Package fastlane checks the release chain of this repository's
// .gitlab-ci.yml for the two properties the pinup fast lane depends on: the
// yasrt include has trigger-pinup switched on, and the job that cuts the tag
// (`release`) needs the job that publishes the binaries
// (`upload:package-registry`). yasrt's release:trigger-pinup waits for
// `release`, so with that need the lane starts only once the package the
// consumers fetch exists. Without it the tag - and the lane - could come
// first, and the lane would find nothing to bump (the 47-second case of
// release-tools!291).
//
// A purpose-built reader, not a YAML parser: the module has no YAML
// dependency and this is not worth one. It reads exactly the two shapes this
// file uses and fails on anything it does not recognise.
package fastlane

import (
	"errors"
	"slices"
	"strings"
)

var (
	// ErrTriggerOff: the yasrt include does not set trigger-pinup: 'true'.
	ErrTriggerOff = errors.New("fastlane: the yasrt include does not set trigger-pinup: 'true' - a release starts no fast lane")
	// ErrTagBeforePublish: `release` does not need the publish job, so the
	// tag and the lane can come before the package exists.
	ErrTagBeforePublish = errors.New("fastlane: `release` does not need upload:package-registry - the tag, and the fast lane after it, can come before the package is published")
	// ErrNoReleaseJob: the file defines no top-level `release` job.
	ErrNoReleaseJob = errors.New("fastlane: no top-level `release:` job found")
)

// PublishJob is the job that makes a release fetchable for its consumers.
const PublishJob = "upload:package-registry"

// Check returns nil when both properties hold, else the first that does not.
func Check(ci string) error {
	if !triggerOn(ci) {
		return ErrTriggerOff
	}
	needs, ok := releaseNeeds(ci)
	if !ok {
		return ErrNoReleaseJob
	}
	if !slices.Contains(needs, PublishJob) {
		return ErrTagBeforePublish
	}
	return nil
}

// triggerOn finds the include of release-tools/yasrt and looks for
// trigger-pinup: 'true' among the lines up to the next list item at the
// same indentation.
func triggerOn(ci string) bool {
	lines := strings.Split(ci, "\n")
	for i, l := range lines {
		if !strings.Contains(l, "release-tools/yasrt@") {
			continue
		}
		indent := len(l) - len(strings.TrimLeft(l, " "))
		for _, next := range lines[i+1:] {
			trimmed := strings.TrimLeft(next, " ")
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			ni := len(next) - len(trimmed)
			if ni <= indent {
				break
			}
			if v, ok := strings.CutPrefix(trimmed, "trigger-pinup:"); ok {
				v = strings.Trim(strings.TrimSpace(v), `'"`)
				return v == "true"
			}
		}
	}
	return false
}

// releaseNeeds returns the job names in the `needs` of the top-level
// `release` job, in either the inline ([a, b]) or the block (- a) form, and
// the plain-name or `job: name` entry form.
func releaseNeeds(ci string) ([]string, bool) {
	lines := strings.Split(ci, "\n")
	for i, l := range lines {
		if l != "release:" {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			l := lines[j]
			if l != "" && l[0] != ' ' && l[0] != '#' {
				return nil, true // the next top-level key: no needs
			}
			v, ok := strings.CutPrefix(strings.TrimSpace(l), "needs:")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			if strings.HasPrefix(v, "[") {
				var out []string
				for item := range strings.SplitSeq(strings.Trim(v, "[]"), ",") {
					out = append(out, name(item))
				}
				return out, true
			}
			var out []string
			for _, item := range lines[j+1:] {
				t := strings.TrimSpace(item)
				e, ok := strings.CutPrefix(t, "- ")
				if !ok {
					if strings.HasPrefix(t, "job:") || strings.HasPrefix(t, "artifacts:") || strings.HasPrefix(t, "optional:") {
						continue
					}
					break
				}
				out = append(out, name(e))
			}
			return out, true
		}
		return nil, true
	}
	return nil, false
}

// name reads "a", "'a'" or "job: a" / "{ job: a, ... }" as a.
func name(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "{}")
	if _, v, ok := strings.Cut(s, "job:"); ok {
		s, _, _ = strings.Cut(v, ",")
	}
	return strings.Trim(strings.TrimSpace(s), `'"`)
}
