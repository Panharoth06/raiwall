package ast

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// XSSChop performs bounded AST context verification for cross-site scripting using synthetic HTML contexts.
type XSSChop struct {
	MaxParamSize int
	Timeout      time.Duration
}

// NewXSSChop creates a new XSSChop verifier with default production constraints.
func NewXSSChop() *XSSChop {
	return &XSSChop{
		MaxParamSize: DefaultMaxParamSize,
		Timeout:      DefaultASTTimeout,
	}
}

// Dangerous HTML tags capable of script execution or external resource loading
var dangerousTags = map[string]bool{
	"script":   true,
	"iframe":   true,
	"embed":    true,
	"object":   true,
	"applet":   true,
	"svg":      true,
	"math":     true,
	"base":     true,
	"form":     true,
	"meta":     true,
	"link":     true,
	"style":    true,
	"audio":    true,
	"video":    true,
	"body":     true,
	"frameset": true,
	"frame":    true,
}

// Verify evaluates candidate input against synthetic HTML contexts.
// Returns a Verdict indicating whether XSS breakout occurred, or if timeout was reached.
func (x *XSSChop) Verify(ctx context.Context, input string) (*Verdict, error) {
	maxSize := x.MaxParamSize
	if maxSize <= 0 {
		maxSize = DefaultMaxParamSize
	}
	if len(input) > maxSize {
		return VerdictAllow, nil
	}

	timeout := x.Timeout
	if timeout <= 0 {
		timeout = DefaultASTTimeout
	}
	evalCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		verdict *Verdict
		err     error
	}
	resChan := make(chan result, 1)

	go func() {
		v, err := x.probe(input)
		resChan <- result{verdict: v, err: err}
	}()

	select {
	case <-evalCtx.Done():
		if evalCtx.Err() == context.DeadlineExceeded {
			return &Verdict{
				Action: ActionAudit,
				RuleID: "PARSER_TIMEOUT",
				Reason: "HTML/XSS AST parser execution deadline exceeded",
			}, nil
		}
		return VerdictAllow, evalCtx.Err()
	case res := <-resChan:
		return res.verdict, res.err
	}
}

// probe evaluates input within synthetic HTML contexts.
func (x *XSSChop) probe(input string) (*Verdict, error) {
	if len(input) == 0 {
		return VerdictAllow, nil
	}

	lower := strings.ToLower(strings.TrimSpace(input))

	// 1. Direct pseudo-protocol URI inspection
	if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "vbscript:") ||
		strings.HasPrefix(lower, "data:text/html") {
		return &Verdict{
			Action: ActionBlock,
			RuleID: "SEMANTIC_XSS",
			Reason: "Cross-site scripting detected via script pseudo-protocol",
		}, nil
	}

	// 2. Context 2: Quoted attribute context probe (<div data-val="<INPUT>"></div>)
	attrProbe := "<div data-val=\"" + input + "\"></div>"
	if breakout, reason := analyzeAttributeBreakout(attrProbe); breakout {
		return &Verdict{
			Action: ActionBlock,
			RuleID: "SEMANTIC_XSS",
			Reason: fmt.Sprintf("Cross-site scripting detected via attribute breakout: %s", reason),
		}, nil
	}

	// 3. Context 3: Element body context probe (<div><INPUT></div>)
	bodyProbe := "<div>" + input + "</div>"
	if breakout, reason := analyzeBodyBreakout(bodyProbe); breakout {
		return &Verdict{
			Action: ActionBlock,
			RuleID: "SEMANTIC_XSS",
			Reason: fmt.Sprintf("Cross-site scripting detected via HTML tag injection: %s", reason),
		}, nil
	}

	return VerdictAllow, nil
}

// analyzeAttributeBreakout checks if input in <div data-val="<INPUT>"></div> breaks out of the attribute
func analyzeAttributeBreakout(htmlSnippet string) (bool, string) {
	tokenizer := html.NewTokenizer(strings.NewReader(htmlSnippet))

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			if tokenizer.Err() == io.EOF {
				break
			}
			return false, ""
		}

		tok := tokenizer.Token()

		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			tag := strings.ToLower(tok.Data)
			if dangerousTags[tag] {
				return true, "injected executable HTML tag <" + tag + ">"
			}

			for _, attr := range tok.Attr {
				k := strings.ToLower(attr.Key)
				v := strings.ToLower(attr.Val)

				if strings.HasPrefix(k, "on") {
					return true, "injected event handler attribute (" + k + ")"
				}
				if (k == "href" || k == "src" || k == "action" || k == "formaction") &&
					(strings.HasPrefix(v, "javascript:") || strings.HasPrefix(v, "vbscript:") || strings.HasPrefix(v, "data:text/html")) {
					return true, "script pseudo-protocol in attribute " + k
				}
			}

			if tag == "div" {
				for _, attr := range tok.Attr {
					k := strings.ToLower(attr.Key)
					if k != "data-val" && strings.HasPrefix(k, "on") {
						return true, "injected event handler attribute (" + k + ")"
					}
				}
			}
		}
	}

	return false, ""
}

// analyzeBodyBreakout checks if input in <div><INPUT></div> injects HTML elements or event handlers
func analyzeBodyBreakout(htmlSnippet string) (bool, string) {
	tokenizer := html.NewTokenizer(strings.NewReader(htmlSnippet))

	depth := 0
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			if tokenizer.Err() == io.EOF {
				break
			}
			return false, ""
		}

		tok := tokenizer.Token()

		switch tt {
		case html.StartTagToken:
			tag := strings.ToLower(tok.Data)
			depth++
			if depth > 1 {
				if dangerousTags[tag] {
					return true, "injected dangerous HTML tag <" + tag + ">"
				}
				for _, attr := range tok.Attr {
					k := strings.ToLower(attr.Key)
					v := strings.ToLower(attr.Val)
					if strings.HasPrefix(k, "on") {
						return true, "injected event handler attribute (" + k + ") on <" + tag + ">"
					}
					if strings.HasPrefix(v, "javascript:") {
						return true, "injected javascript: pseudo-protocol on <" + tag + ">"
					}
				}
			}

		case html.SelfClosingTagToken:
			tag := strings.ToLower(tok.Data)
			if dangerousTags[tag] {
				return true, "injected dangerous self-closing HTML tag <" + tag + "/>"
			}
			for _, attr := range tok.Attr {
				k := strings.ToLower(attr.Key)
				v := strings.ToLower(attr.Val)
				if strings.HasPrefix(k, "on") {
					return true, "injected event handler attribute (" + k + ") on <" + tag + "/>"
				}
				if strings.HasPrefix(v, "javascript:") {
					return true, "injected javascript: pseudo-protocol on <" + tag + "/>"
				}
			}

		case html.EndTagToken:
			depth--
		}
	}

	return false, ""
}
