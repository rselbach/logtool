package importer

import (
	"fmt"
	"strings"
)

// AccessFormat represents the structure of access/error logs.
type AccessFormat string

const (
	FormatCaddy AccessFormat = "caddy"
	FormatNginx AccessFormat = "nginx"
)

// ParseAccessFormat converts a string to a supported format.
func ParseAccessFormat(s string) (AccessFormat, error) {
	switch AccessFormat(strings.ToLower(strings.TrimSpace(s))) {
	case FormatCaddy:
		return FormatCaddy, nil
	case FormatNginx:
		return FormatNginx, nil
	default:
		return "", fmt.Errorf("unsupported format %q", s)
	}
}
