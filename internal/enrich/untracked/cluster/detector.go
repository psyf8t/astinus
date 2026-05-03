package cluster

import (
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/psyf8t/astinus/internal/image/layer"
)

// Options configures DetectClusters.
type Options struct {
	// MaxAnchorBytes caps how many bytes the detector reads from a
	// single anchor file. Real package-manifest files are < 256 KiB
	// in 99.9 % of cases; the cap defends against a pathological
	// 1 GiB `package.json` consuming memory before the parser bails.
	// Zero → 256 KiB.
	MaxAnchorBytes int64

	// SkipDensity disables the density-stage scorer when true. The
	// anchor stage still runs. Useful for tests that want to assert
	// only the anchor classification.
	SkipDensity bool

	// MinDirChildren skips density scoring on directories with
	// fewer than this many immediate entries. Suppresses false
	// positives on tiny directories that happen to have a
	// version-pattern name (e.g. `/var/cache/build-1.0/`). Zero →
	// 3.
	MinDirChildren int
}

// DetectClusters runs the two-stage detector against img and returns
// the resulting clusters. Each cluster carries its identity, root
// path, and the visible files claimed under that root (respecting
// nested anchors — a parent cluster does not include files that
// belong to a deeper anchor).
//
// The function performs ONE walk over the image's visible files via
// `layer.WalkFiles` (the same primitive the untracked enricher uses).
// For most files the visitor reads no body — only files whose
// basename matches an anchor rule have their bytes parsed.
func DetectClusters(ctx context.Context, img v1.Image, opts Options) ([]Cluster, error) {
	if img == nil {
		return nil, fmt.Errorf("cluster: nil image")
	}
	maxAnchor := opts.MaxAnchorBytes
	if maxAnchor <= 0 {
		maxAnchor = 256 << 10
	}

	allFiles := make([]fileMeta, 0, 1024)
	anchorClusters := make([]Cluster, 0, 8)

	visitor := func(_ context.Context, fe layer.FileEntry, body io.Reader) error {
		size := int64(0)
		if fe.Header != nil {
			size = fe.Header.Size
		}
		allFiles = append(allFiles, fileMeta{path: fe.Path, size: size})
		ext := matchAnchor(fe.Path)
		if ext == nil {
			return nil
		}
		buf, err := io.ReadAll(io.LimitReader(body, maxAnchor))
		if err != nil {
			//nolint:nilerr // anchor read failure must not abort the walk; the dir falls through to density scoring
			return nil
		}
		ident, err := ext(fe.Path, buf)
		if err != nil {
			//nolint:nilerr // malformed manifest is logged via callers; the dir falls through to density scoring
			return nil
		}
		anchorClusters = append(anchorClusters, Cluster{
			Identity: ident,
			Root:     anchorRoot(fe.Path, ident),
		})
		return nil
	}

	if err := layer.WalkFiles(ctx, img, visitor); err != nil {
		return nil, fmt.Errorf("cluster: walk: %w", err)
	}

	// Sort by depth (deepest first) so a nested anchor wins over a
	// shallower one when a file would otherwise belong to both.
	sort.SliceStable(anchorClusters, func(i, j int) bool {
		return depthOf(anchorClusters[i].Root) > depthOf(anchorClusters[j].Root)
	})

	assignFilesToClusters(anchorClusters, allFiles)

	if opts.SkipDensity {
		return anchorClusters, nil
	}

	density := detectDensityClusters(allFiles, anchorClusters, opts.MinDirChildren)
	return append(anchorClusters, density...), nil
}

// fileMeta is the per-file record the detector keeps in memory while
// it processes the walk. We do NOT keep file bodies — only path +
// size are needed for cluster assignment and density scoring.
type fileMeta struct {
	path string
	size int64
}

// anchorRoot returns the cluster root for an anchor file. For most
// anchors it's `dirname(anchorPath)`. The Python wheel
// `<x>.dist-info/METADATA` is special — its real cluster root is
// the parent of `*.dist-info` (the package's installed location).
func anchorRoot(anchorPath string, ident Identity) string {
	dir := path.Dir(anchorPath)
	if dir == "." {
		dir = ""
	}
	if ident.DetectionMethod == "anchor:dist-info/METADATA" {
		return path.Dir(dir)
	}
	return dir
}

// depthOf returns the number of `/`-separated segments in p. Used
// for the deepest-anchor-wins sort.
func depthOf(p string) int {
	if p == "" {
		return 0
	}
	return strings.Count(p, "/") + 1
}

// assignFilesToClusters fills cluster.Files for every cluster,
// respecting nesting: a file is assigned to the DEEPEST cluster
// whose root contains it. Clusters must already be sorted by depth
// (deepest first).
func assignFilesToClusters(clusters []Cluster, files []fileMeta) {
	for i := range clusters {
		clusters[i].Files = clusters[i].Files[:0]
		clusters[i].TotalSize = 0
	}
	for _, f := range files {
		for j := range clusters {
			if clusters[j].Within(f.path) {
				clusters[j].Files = append(clusters[j].Files, f.path)
				clusters[j].TotalSize += f.size
				break
			}
		}
	}
}

// dirInfo is the per-directory aggregate the density stage builds in
// its first pass.
type dirInfo struct {
	children   map[string]struct{}
	fileCount  int
	anyClaimed bool
}

// detectDensityClusters runs the density stage over directories not
// already covered by an anchor cluster. Returns the additional
// clusters produced.
func detectDensityClusters(files []fileMeta, anchorClusters []Cluster, minChildren int) []Cluster {
	if minChildren < 1 {
		minChildren = 3
	}
	dirs := buildDirIndex(files, anchorClusters)
	dirNames := sortedDirNames(dirs)

	out := make([]Cluster, 0, 4)
	scored := make(map[string]struct{}, len(dirs))
	for _, dirName := range dirNames {
		info := dirs[dirName]
		if !densityCandidate(dirName, info, minChildren, scored) {
			continue
		}
		c, ok := tryEmitDensityCluster(dirName, info, files, anchorClusters)
		if !ok {
			continue
		}
		out = append(out, c)
		markScored(dirName, scored)
	}
	return out
}

// buildDirIndex aggregates per-directory children sets + recursive
// file counts + the "any descendant already claimed by an anchor"
// flag, in one pass over the file list.
func buildDirIndex(files []fileMeta, anchorClusters []Cluster) map[string]*dirInfo {
	dirs := make(map[string]*dirInfo, len(files)/4)
	get := func(p string) *dirInfo {
		d, ok := dirs[p]
		if !ok {
			d = &dirInfo{children: map[string]struct{}{}}
			dirs[p] = d
		}
		return d
	}
	for _, f := range files {
		claimed := isAnchored(f.path, anchorClusters)
		parent := pathParent(f.path)
		get(parent).children[path.Base(f.path)] = struct{}{}
		for cur := parent; cur != ""; cur = parent2(cur) {
			info := get(cur)
			info.fileCount++
			if claimed {
				info.anyClaimed = true
			}
			if cur == parent {
				continue
			}
			info.children[childUnder(cur, parent)] = struct{}{}
		}
	}
	return dirs
}

func sortedDirNames(dirs map[string]*dirInfo) []string {
	out := make([]string, 0, len(dirs))
	for d := range dirs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// densityCandidate is the cheap pre-screen — gates dirs we'll waste
// scoreDirectory time on.
func densityCandidate(dirName string, info *dirInfo, minChildren int, scored map[string]struct{}) bool {
	if dirName == "" || len(info.children) < minChildren {
		return false
	}
	if info.anyClaimed {
		return false
	}
	return !alreadyScored(dirName, scored)
}

// tryEmitDensityCluster scores the directory and assembles a Cluster
// when the threshold is crossed.
func tryEmitDensityCluster(dirName string, info *dirInfo, files []fileMeta, anchorClusters []Cluster) (Cluster, bool) {
	sig, score := scoreDirectory(dirName, keys(info.children), info.fileCount)
	if score < densityScoreThreshold {
		return Cluster{}, false
	}
	ident, ok := densityIdentity(dirName, sig, score)
	if !ok {
		return Cluster{}, false
	}
	c := Cluster{Identity: ident, Root: dirName}
	for _, f := range files {
		if !c.Within(f.path) {
			continue
		}
		if isAnchored(f.path, anchorClusters) {
			continue
		}
		c.Files = append(c.Files, f.path)
		c.TotalSize += f.size
	}
	return c, true
}

// markScored stamps dirName and every ancestor as scored so the
// next iteration doesn't emit an overlapping outer cluster.
func markScored(dirName string, scored map[string]struct{}) {
	for cur := dirName; cur != ""; cur = parent2(cur) {
		scored[cur] = struct{}{}
	}
}

// pathParent returns path.Dir(p) but with `.` collapsed to `""`
// (the root directory in our canonical-form convention).
func pathParent(p string) string {
	parent := path.Dir(p)
	if parent == "." {
		return ""
	}
	return parent
}

// isAnchored reports whether p sits under any anchor cluster's root.
func isAnchored(p string, anchorClusters []Cluster) bool {
	for j := range anchorClusters {
		if anchorClusters[j].Within(p) {
			return true
		}
	}
	return false
}

// parent2 returns path.Dir(p) but with the empty-root convention:
// the root's parent is "", not ".".
func parent2(p string) string {
	if p == "" || p == "/" {
		return ""
	}
	d := path.Dir(p)
	if d == "." {
		return ""
	}
	return d
}

// childUnder returns the next path segment of `child` immediately
// under `parent` (e.g., parent=`a/b`, child=`a/b/c/d` → "c"). Used
// to record deep file paths as a single child segment in the
// ancestor's children set.
func childUnder(parent, child string) string {
	if parent == "" {
		return strings.SplitN(child, "/", 2)[0]
	}
	if !strings.HasPrefix(child, parent+"/") {
		return ""
	}
	rest := child[len(parent)+1:]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// alreadyScored reports whether dirName or any of its ancestors is
// already in scored. Used to suppress overlapping density emissions.
func alreadyScored(dirName string, scored map[string]struct{}) bool {
	for cur := dirName; cur != ""; cur = parent2(cur) {
		if _, ok := scored[cur]; ok {
			return true
		}
	}
	return false
}

// keys returns the sorted set keys (kept stable for deterministic
// scoring evidence in logs/tests).
func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
