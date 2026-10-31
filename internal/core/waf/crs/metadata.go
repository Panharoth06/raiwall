package crs

import (
	"bufio"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// RuleMeta is the catalog metadata extracted from a SecRule directive.
type RuleMeta struct {
	ID       int
	Message  string
	Severity string
	Tags     []string
	Phase    int
	File     string
	Line     int
}

var (
	ruleIDPattern   = regexp.MustCompile(`\bid:(\d+)`)
	messagePattern  = regexp.MustCompile(`\bmsg:'([^']*)'`)
	severityPattern = regexp.MustCompile(`\bseverity:'([^']*)'`)
	tagPattern      = regexp.MustCompile(`\btag:'([^']*)'`)
	phasePattern    = regexp.MustCompile(`\bphase:(\d+)`)

	embeddedMetaOnce sync.Once
	embeddedMeta     []RuleMeta
	embeddedMetaErr  error
)

// EmbeddedRuleMetadata returns cached metadata for the vendored CRS rules.
func EmbeddedRuleMetadata() ([]RuleMeta, error) {
	embeddedMetaOnce.Do(func() {
		embeddedMetaErr = fs.WalkDir(rulesFS, "rules", func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".conf") {
				return nil
			}
			data, readErr := rulesFS.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			embeddedMeta = append(embeddedMeta, scanMetadata(string(data), path)...)
			return nil
		})
	})
	return embeddedMeta, embeddedMetaErr
}

// ScanDirectiveMetadata extracts metadata from a ModSecurity directive block.
func ScanDirectiveMetadata(directives string) []RuleMeta {
	return scanMetadata(directives, "")
}

func scanMetadata(text, file string) []RuleMeta {
	var out []RuleMeta
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var pending strings.Builder
	startLine := 0
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if pending.Len() == 0 {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			startLine = lineNo
		}
		if strings.HasSuffix(line, `\`) {
			pending.WriteString(strings.TrimSuffix(line, `\`))
			pending.WriteByte(' ')
			continue
		}
		pending.WriteString(line)
		directive := pending.String()
		pending.Reset()

		if !strings.HasPrefix(directive, "SecRule") {
			continue
		}
		idMatch := ruleIDPattern.FindStringSubmatch(directive)
		if len(idMatch) < 2 {
			continue
		}
		id, err := strconv.Atoi(idMatch[1])
		if err != nil {
			continue
		}
		meta := RuleMeta{ID: id, File: file, Line: startLine}
		if match := messagePattern.FindStringSubmatch(directive); len(match) > 1 {
			meta.Message = match[1]
		}
		if match := severityPattern.FindStringSubmatch(directive); len(match) > 1 {
			meta.Severity = strings.ToLower(match[1])
		}
		if match := phasePattern.FindStringSubmatch(directive); len(match) > 1 {
			meta.Phase, _ = strconv.Atoi(match[1])
		}
		for _, match := range tagPattern.FindAllStringSubmatch(directive, -1) {
			if len(match) > 1 {
				meta.Tags = append(meta.Tags, match[1])
			}
		}
		out = append(out, meta)
	}
	return out
}
