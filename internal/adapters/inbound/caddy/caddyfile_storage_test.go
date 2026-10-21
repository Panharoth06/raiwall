package caddy

import (
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/require"
)

func TestCaddyfile_ParseStorage(t *testing.T) {
	input := `raiwall {
		storage {
			store "main_pg" {
				driver postgres
				dsn "postgres://postgres:secret@localhost:5432/raiwall?sslmode=disable"
				max_open 25
				max_idle 5
				retention 720h
				prune_interval 30m
			}
			store "local_sq" {
				driver sqlite
				dsn "file:local.db"
			}
			control main_pg
			telemetry main_pg
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	m := new(Middleware)
	err := m.UnmarshalCaddyfile(d)
	require.NoError(t, err)

	require.NotNil(t, m.StorageConfig)
	require.Equal(t, "main_pg", m.StorageConfig.Control)
	require.Equal(t, "main_pg", m.StorageConfig.Telemetry)
	require.Len(t, m.StorageConfig.Stores, 2)

	pgStore, ok := m.StorageConfig.Stores["main_pg"]
	require.True(t, ok)
	require.Equal(t, "postgres", pgStore.Driver)
	require.Equal(t, "postgres://postgres:secret@localhost:5432/raiwall?sslmode=disable", pgStore.DSN)
	require.Equal(t, 25, pgStore.MaxOpen)
	require.Equal(t, 5, pgStore.MaxIdle)
	require.Equal(t, 720*time.Hour, time.Duration(pgStore.Retention))
	require.Equal(t, 30*time.Minute, time.Duration(pgStore.PruneInterval))

	sqStore, ok := m.StorageConfig.Stores["local_sq"]
	require.True(t, ok)
	require.Equal(t, "sqlite", sqStore.Driver)
	require.Equal(t, "file:local.db", sqStore.DSN)
}

func TestCaddyfile_ParseStorageErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "missing store name",
			input: `raiwall {
				storage {
					store
				}
			}`,
		},
		{
			name: "invalid max_open",
			input: `raiwall {
				storage {
					store "pg" {
						max_open invalid
					}
				}
			}`,
		},
		{
			name: "unrecognized option",
			input: `raiwall {
				storage {
					invalid_opt foo
				}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			m := new(Middleware)
			err := m.UnmarshalCaddyfile(d)
			require.Error(t, err)
		})
	}
}
