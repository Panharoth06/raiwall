package sqlite

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"time"
)

func (s *telemetryDriverStmt) Exec(args []driver.Value) (driver.Result, error) {
	q := strings.TrimSpace(strings.ToUpper(s.query))

	if strings.HasPrefix(q, "PRAGMA") ||
		strings.HasPrefix(q, "CREATE TABLE") ||
		strings.HasPrefix(q, "CREATE INDEX") {
		return driver.RowsAffected(0), nil
	}

	if strings.HasPrefix(q, "INSERT") {
		if len(args) >= 21 {
			tsStr := fmt.Sprint(args[1])
			ts, _ := time.Parse(time.RFC3339Nano, tsStr)
			if ts.IsZero() {
				ts, _ = time.Parse(time.RFC3339, tsStr)
			}

			var asn uint
			if v, ok := args[10].(uint); ok {
				asn = v
			} else if v, ok := args[10].(int64); ok {
				asn = uint(v)
			}

			var lat, lon float64
			if v, ok := args[12].(float64); ok {
				lat = v
			}
			if v, ok := args[13].(float64); ok {
				lon = v
			}

			var latency int64
			if v, ok := args[19].(int64); ok {
				latency = v
			}
			var status int
			if v, ok := args[20].(int64); ok {
				status = int(v)
			} else if v, ok := args[20].(int); ok {
				status = v
			}

			var payloadLoc, matchedToken, attackCategory, respHeaders string
			var respBody []byte
			if len(args) >= 22 {
				payloadLoc = fmt.Sprint(args[21])
			}
			if len(args) >= 23 {
				matchedToken = fmt.Sprint(args[22])
			}
			if len(args) >= 24 {
				attackCategory = fmt.Sprint(args[23])
			}
			if len(args) >= 25 {
				respHeaders = fmt.Sprint(args[24])
			}
			if len(args) >= 26 {
				if b, ok := args[25].([]byte); ok {
					respBody = b
				} else if str, ok := args[25].(string); ok {
					respBody = []byte(str)
				}
			}

			row := &telemetryDBRow{
				EventID:         fmt.Sprint(args[0]),
				Timestamp:       ts,
				Host:            fmt.Sprint(args[2]),
				Path:            fmt.Sprint(args[3]),
				Method:          fmt.Sprint(args[4]),
				ClientIP:        fmt.Sprint(args[5]),
				JA4:             fmt.Sprint(args[6]),
				Country:         fmt.Sprint(args[7]),
				Continent:       fmt.Sprint(args[8]),
				City:            fmt.Sprint(args[9]),
				ASN:             asn,
				ASOrg:           fmt.Sprint(args[11]),
				Latitude:        lat,
				Longitude:       lon,
				RuleID:          fmt.Sprint(args[14]),
				Action:          fmt.Sprint(args[15]),
				Severity:        fmt.Sprint(args[16]),
				Headers:         fmt.Sprint(args[17]),
				Payload:         fmt.Sprint(args[18]),
				LatencyUs:       latency,
				StatusCode:      status,
				PayloadLocation: payloadLoc,
				MatchedToken:    matchedToken,
				AttackCategory:  attackCategory,
				ResponseHeaders: respHeaders,
				ResponseBody:    respBody,
			}
			s.conn.db.insert(row)
			return driver.RowsAffected(1), nil
		}
	}

	if strings.HasPrefix(q, "DELETE") {
		if len(args) >= 1 {
			cutoffStr := fmt.Sprint(args[0])
			cutoff, _ := time.Parse(time.RFC3339Nano, cutoffStr)
			if cutoff.IsZero() {
				cutoff, _ = time.Parse(time.RFC3339, cutoffStr)
			}
			deleted := s.conn.db.deleteBefore(cutoff)
			return driver.RowsAffected(deleted), nil
		}
	}

	return driver.RowsAffected(0), nil
}
