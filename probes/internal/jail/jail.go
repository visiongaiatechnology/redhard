// Package jail enforces fail-closed path isolation for destructive and file-writing probes.
package jail

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	// ErrInvalidPath indicates a malformed, empty, or relative path.
	ErrInvalidPath = errors.New("invalid sandbox path")
	// ErrOutsideJail indicates a path resolved outside all allowed sandbox roots.
	ErrOutsideJail = errors.New("path resolves outside allowed sandbox roots")
)

// Jail restricts filesystem operations to a fixed list of allowed root directories.
type Jail struct {
	AllowedRoots []string
}

// DefaultSandboxJail returns the production fail-closed sandbox policy.
// Probes may operate only under /tmp/hardred-sandbox or /dev/shm/hardred-sandbox.
func DefaultSandboxJail() *Jail {
	return &Jail{
		AllowedRoots: []string{
			"/tmp/hardred-sandbox",
			"/dev/shm/hardred-sandbox",
		},
	}
}

// Validate verifies that target is an absolute path resolving inside one of AllowedRoots.
// On Linux it resolves symlinks on existing ancestors to block symlink escapes.
func (j *Jail) Validate(target string) (string, error) {
	if j == nil || len(j.AllowedRoots) == 0 {
		return "", fmt.Errorf("%w: no allowed roots configured", ErrOutsideJail)
	}
	trimmed := strings.TrimSpace(target)
	if trimmed == "" || strings.ContainsRune(trimmed, 0) {
		return "", fmt.Errorf("%w: empty or null byte", ErrInvalidPath)
	}

	if runtime.GOOS == "linux" || strings.HasPrefix(trimmed, "/") {
		return j.validatePOSIX(trimmed)
	}
	return j.validateNative(trimmed)
}

func (j *Jail) validatePOSIX(target string) (string, error) {
	if strings.Contains(target, "\\") || !strings.HasPrefix(target, "/") {
		return "", fmt.Errorf("%w: %q must be a POSIX absolute path", ErrInvalidPath, target)
	}
	cleaned := path.Clean(target)
	if !pathInRootsPOSIX(cleaned, j.AllowedRoots) {
		return "", fmt.Errorf("%w: %q is outside %v", ErrOutsideJail, cleaned, j.AllowedRoots)
	}

	if runtime.GOOS != "linux" {
		return cleaned, nil
	}

	resolvedTarget, err := evalPrefixSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("%w: symlink resolution failed for %q: %v", ErrOutsideJail, cleaned, err)
	}
	resolvedRoots := make([]string, 0, len(j.AllowedRoots))
	for _, r := range j.AllowedRoots {
		rc, rErr := evalPrefixSymlinks(path.Clean(r))
		if rErr != nil {
			rc = path.Clean(r)
		}
		resolvedRoots = append(resolvedRoots, rc)
	}
	if !pathInRootsPOSIX(resolvedTarget, resolvedRoots) {
		return "", fmt.Errorf("%w: resolved path %q escapes jail %v", ErrOutsideJail, resolvedTarget, resolvedRoots)
	}
	return resolvedTarget, nil
}

func (j *Jail) validateNative(target string) (string, error) {
	if !filepath.IsAbs(target) {
		return "", fmt.Errorf("%w: %q is not absolute", ErrInvalidPath, target)
	}
	cleaned := filepath.Clean(target)
	resolvedTarget, err := evalPrefixSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOutsideJail, err)
	}
	for _, root := range j.AllowedRoots {
		if !filepath.IsAbs(root) {
			continue
		}
		resolvedRoot, rErr := evalPrefixSymlinks(filepath.Clean(root))
		if rErr != nil {
			resolvedRoot = filepath.Clean(root)
		}
		if isWithinNative(resolvedTarget, resolvedRoot) {
			return resolvedTarget, nil
		}
	}
	return "", fmt.Errorf("%w: %q is outside %v", ErrOutsideJail, resolvedTarget, j.AllowedRoots)
}

// SafeChildPath validates a single-segment filename and joins it under sandboxDir.
func SafeChildPath(sandboxDir, name string) (string, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return "", fmt.Errorf("%w: invalid child filename %q", ErrInvalidPath, name)
	}
	if strings.HasPrefix(sandboxDir, "/") && runtime.GOOS != "windows" {
		joined := path.Join(sandboxDir, name)
		if !strings.HasPrefix(joined, strings.TrimRight(sandboxDir, "/")+"/") {
			return "", fmt.Errorf("%w: %q escapes %q", ErrOutsideJail, joined, sandboxDir)
		}
		return joined, nil
	}
	joined := filepath.Join(sandboxDir, name)
	if !isWithinNative(joined, sandboxDir) || joined == filepath.Clean(sandboxDir) {
		return "", fmt.Errorf("%w: %q escapes %q", ErrOutsideJail, joined, sandboxDir)
	}
	return joined, nil
}

func pathInRootsPOSIX(cleaned string, roots []string) bool {
	for _, root := range roots {
		rc := path.Clean(root)
		if !strings.HasPrefix(rc, "/") {
			continue
		}
		if cleaned == rc || strings.HasPrefix(cleaned, rc+"/") {
			return true
		}
	}
	return false
}

func isWithinNative(target, root string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// evalPrefixSymlinks resolves symlinks for the deepest existing ancestor of p
// and re-appends the remaining non-existent path components.
func evalPrefixSymlinks(p string) (string, error) {
	cur := p
	var suffix []string
	for {
		if _, err := os.Lstat(cur); err == nil {
			resolved, rErr := filepath.EvalSymlinks(cur)
			if rErr != nil {
				return "", rErr
			}
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			if runtime.GOOS == "linux" {
				return filepath.ToSlash(resolved), nil
			}
			return resolved, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p, nil
		}
		suffix = append(suffix, filepath.Base(cur))
		cur = parent
	}
}
