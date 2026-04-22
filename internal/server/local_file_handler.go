package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
)

type localFileHandler struct {
	routePrefix string
	basePath    string
	browse      bool
}

type localDirEntry struct {
	Name    string
	Href    string
	Type    string
	Size    string
	ModTime string
}

func newLocalFileHandler(routePrefix, basePath string, browse bool) (http.Handler, error) {
	absBasePath, err := filepath.Abs(filepath.Clean(strings.TrimSpace(basePath)))
	if err != nil {
		return nil, fmt.Errorf("resolve base path: %w", err)
	}
	if absBasePath == "" || !filepath.IsAbs(absBasePath) {
		return nil, fmt.Errorf("base path must be absolute")
	}
	prefix := strings.TrimSpace(routePrefix)
	if prefix == "" {
		prefix = "/"
	}
	return &localFileHandler{
		routePrefix: prefix,
		basePath:    absBasePath,
		browse:      browse,
	}, nil
}

func (h *localFileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	relPath, ok := localFileRelativePath(r.URL.Path, h.routePrefix)
	if !ok {
		http.NotFound(w, r)
		return
	}

	targetPath, err := h.resolveTargetPath(relPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// targetPath is already symlink-resolved; os.Stat here will not follow further symlinks
	// outside the base directory.
	info, err := os.Stat(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !info.IsDir() {
		http.ServeFile(w, r, targetPath)
		return
	}

	if !strings.HasSuffix(r.URL.Path, "/") {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
		return
	}

	indexPath := filepath.Join(targetPath, "index.html")
	if indexInfo, indexErr := os.Stat(indexPath); indexErr == nil && !indexInfo.IsDir() {
		http.ServeFile(w, r, indexPath)
		return
	}

	if h.browse {
		h.serveDirectoryListing(w, r, targetPath)
		return
	}

	http.NotFound(w, r)
}

func (h *localFileHandler) resolveTargetPath(relPath string) (string, error) {
	decodedPath, err := url.PathUnescape(relPath)
	if err != nil {
		return "", fmt.Errorf("decode path: %w", err)
	}

	cleanURLPath := path.Clean("/" + strings.TrimPrefix(decodedPath, "/"))
	cleanRelPath := strings.TrimPrefix(cleanURLPath, "/")
	targetPath := filepath.Join(h.basePath, filepath.FromSlash(cleanRelPath))
	absTargetPath, err := filepath.Abs(targetPath)
	if err != nil {
		return "", fmt.Errorf("resolve target path: %w", err)
	}

	relToBase, err := filepath.Rel(h.basePath, absTargetPath)
	if err != nil {
		return "", fmt.Errorf("check target path: %w", err)
	}
	if relToBase == ".." || strings.HasPrefix(relToBase, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes base directory")
	}

	// Resolve symlinks and re-check containment to prevent symlink escape.
	resolvedTargetPath, err := filepath.EvalSymlinks(absTargetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path not found: %w", os.ErrNotExist)
		}
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	resolvedBase, err := filepath.EvalSymlinks(h.basePath)
	if err != nil {
		return "", fmt.Errorf("resolve base symlinks: %w", err)
	}
	relToResolvedBase, err := filepath.Rel(resolvedBase, resolvedTargetPath)
	if err != nil {
		return "", fmt.Errorf("check resolved target path: %w", err)
	}
	if relToResolvedBase == ".." || strings.HasPrefix(relToResolvedBase, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes base directory")
	}

	return resolvedTargetPath, nil
}

func localFileRelativePath(requestPath, routePrefix string) (string, bool) {
	if routePrefix == "/" {
		return strings.TrimPrefix(requestPath, "/"), true
	}
	if !strings.HasPrefix(requestPath, routePrefix) {
		return "", false
	}
	rel := strings.TrimPrefix(requestPath, routePrefix)
	return strings.TrimPrefix(rel, "/"), true
}

func (h *localFileHandler) serveDirectoryListing(w http.ResponseWriter, r *http.Request, targetPath string) {
	entries, err := os.ReadDir(targetPath)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	baseURLPath := r.URL.Path
	if baseURLPath == "" {
		baseURLPath = "/"
	}
	if !strings.HasSuffix(baseURLPath, "/") {
		baseURLPath += "/"
	}

	rows := make([]localDirEntry, 0, len(entries))
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}

		name := entry.Name()
		displayName := name
		entryType := "file"
		size := strconv.FormatInt(info.Size(), 10)
		if info.IsDir() {
			displayName += "/"
			entryType = "dir"
			size = "-"
		}

		hrefName := url.PathEscape(name)
		if info.IsDir() {
			hrefName += "/"
		}

		rows = append(rows, localDirEntry{
			Name:    displayName,
			Href:    baseURLPath + hrefName,
			Type:    entryType,
			Size:    size,
			ModTime: info.ModTime().UTC().Format(time.RFC3339),
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Type != rows[j].Type {
			return rows[i].Type == "dir"
		}
		return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name)
	})

	component := renderDirectoryListingComponent(r.URL.Path, rows)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := component.Render(templ.InitializeContext(r.Context()), w); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func renderDirectoryListingComponent(urlPath string, rows []localDirEntry) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		if _, err := io.WriteString(w, "<!doctype html><html><head><meta charset=\"utf-8\"><title>Directory listing</title><style>body{font-family:sans-serif;margin:24px;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;text-align:left;}th{background:#f3f3f3;}tr:nth-child(even){background:#fafafa;}a{text-decoration:none;}</style></head><body>"); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "<h1>Directory listing for "+templ.EscapeString(urlPath)+"</h1><table><thead><tr><th>Name</th><th>Type</th><th>Size (bytes)</th><th>Modified (UTC)</th></tr></thead><tbody>"); err != nil {
			return err
		}
		for _, row := range rows {
			if _, err := io.WriteString(w, "<tr><td><a href=\""+templ.EscapeString(row.Href)+"\">"+templ.EscapeString(row.Name)+"</a></td><td>"+templ.EscapeString(row.Type)+"</td><td>"+templ.EscapeString(row.Size)+"</td><td>"+templ.EscapeString(row.ModTime)+"</td></tr>"); err != nil {
				return err
			}
		}
		_, err := io.WriteString(w, "</tbody></table></body></html>")
		return err
	})
}
