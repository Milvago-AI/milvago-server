package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type InstallerBundle struct {
	Version  string `json:"version"`
	Artifact string `json:"artifact"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

const installerBundleLimit int64 = 256 * 1024 * 1024

// releaseCacheEntry memoizes one platform artifact digest. It is reused only
// while the file's path, size and modification time are exactly what they were
// when the hash was computed; any change forces a full re-read and re-hash.
type releaseCacheEntry struct {
	path   string
	size   int64
	mtime  time.Time
	sha256 string
}

// releaseBundle is installerBundle with the artifact digest memoized on the
// server: the file is re-read and re-hashed only when its (path, size, mtime)
// changes. Every cheap check — Lstat, regularity, SameFile, size — still runs
// on every call, so a swapped or removed artifact is still caught immediately.
func (a *App) releaseBundle(platform string) (InstallerBundle, string, error) {
	return installerBundleDigest(platform, a)
}

// artifactDigest returns the SHA-256 of an already-opened release artifact,
// serving the memoized value while (path, size, mtime) is unchanged.
// The lock guards the map and nothing else. Hashing runs outside it, deliberately:
// the artifact reaches installerBundleLimit (256 MiB) and there is one mutex for the
// whole cache, so holding it across io.Copy made every concurrent installer download
// queue behind whichever one was hashing -- including downloads for a different
// platform, which share nothing but the mutex. Two callers racing on a cold entry now
// hash the same file twice and write the same value; that is cheaper than serializing
// the fleet.
func (a *App) artifactDigest(platform, path string, artifact *os.File, before os.FileInfo) (string, error) {
	a.releaseCacheMu.Lock()
	entry, ok := a.releaseCache[platform]
	a.releaseCacheMu.Unlock()
	if ok && entry.path == path && entry.size == before.Size() && entry.mtime.Equal(before.ModTime()) {
		return entry.sha256, nil
	}
	digest := sha256.New()
	size, err := io.Copy(digest, io.LimitReader(artifact, installerBundleLimit+1))
	if err != nil || size != before.Size() {
		return "", errors.New("release artifact unreadable")
	}
	sum := hex.EncodeToString(digest.Sum(nil))
	a.releaseCacheMu.Lock()
	defer a.releaseCacheMu.Unlock()
	if a.releaseCache == nil {
		a.releaseCache = map[string]releaseCacheEntry{}
	}
	a.releaseCache[platform] = releaseCacheEntry{path: path, size: before.Size(), mtime: before.ModTime(), sha256: sum}
	return sum, nil
}

func installerBundleDigest(platform string, cache *App) (InstallerBundle, string, error) {
	var bundle InstallerBundle
	unavailable := func() (InstallerBundle, string, error) {
		return bundle, "", apiError{503, "installer_unavailable", "A verified installer release is not available for this platform."}
	}
	if !slices.Contains([]string{"windows", "linux"}, platform) {
		return unavailable()
	}
	directory := os.Getenv("MILVAGO_INSTALLER_DIRECTORY")
	if directory == "" {
		return unavailable()
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return unavailable()
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return unavailable()
	}
	manifest := filepath.Join(directory, Edition+"-"+platform+".json")
	info, err = os.Lstat(manifest)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return unavailable()
	}
	file, err := os.Open(manifest)
	if err != nil {
		return unavailable()
	}
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	file.Close()
	if err != nil || len(raw) > 65536 {
		return unavailable()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&bundle) != nil || decoder.Decode(&struct{}{}) != io.EOF || !versionPattern.MatchString(bundle.Version) || !digestPattern.MatchString(bundle.SHA256) || bundle.Size < 1 || bundle.Size > installerBundleLimit || bundle.Artifact == "" || len(bundle.Artifact) > 160 || filepath.Base(bundle.Artifact) != bundle.Artifact || strings.ContainsAny(bundle.Artifact, "/\\") {
		return unavailable()
	}
	extension := ".msi"
	if platform == "linux" {
		extension = ".tar.gz"
	}
	if !strings.HasSuffix(bundle.Artifact, extension) {
		return unavailable()
	}
	path := filepath.Join(directory, bundle.Artifact)
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() != bundle.Size {
		return unavailable()
	}
	artifact, err := os.Open(path)
	if err != nil {
		return unavailable()
	}
	defer artifact.Close()
	opened, err := artifact.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return unavailable()
	}
	if cache != nil {
		if sum, err := cache.artifactDigest(platform, path, artifact, before); err != nil || sum != bundle.SHA256 {
			return unavailable()
		}
	} else {
		digest := sha256.New()
		size, err := io.Copy(digest, io.LimitReader(artifact, installerBundleLimit+1))
		if err != nil || size != bundle.Size || hex.EncodeToString(digest.Sum(nil)) != bundle.SHA256 {
			return unavailable()
		}
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return unavailable()
	}
	return bundle, path, nil
}
