package rate

import (
	"path"
	"strings"
)

// DefaultStaticExtensions contains file extensions typically considered static assets.
var DefaultStaticExtensions = map[string]struct{}{
	".css":   {},
	".js":    {},
	".mjs":   {},
	".map":   {},
	".ico":   {},
	".png":   {},
	".jpg":   {},
	".jpeg":  {},
	".gif":   {},
	".svg":   {},
	".webp":  {},
	".avif":  {},
	".bmp":   {},
	".woff":  {},
	".woff2": {},
	".ttf":   {},
	".otf":   {},
	".eot":   {},
	".mp4":   {},
	".webm":  {},
	".mp3":   {},
}

// IsStaticAssetPath checks whether a URL path targets a static asset file extension.
func IsStaticAssetPath(urlPath string, customExts []string) bool {
	ext := strings.ToLower(path.Ext(urlPath))
	if ext == "" {
		return false
	}

	if _, exists := DefaultStaticExtensions[ext]; exists {
		return true
	}

	for _, custom := range customExts {
		if strings.EqualFold(ext, custom) || strings.EqualFold(ext, "."+strings.TrimPrefix(custom, ".")) {
			return true
		}
	}

	return false
}
