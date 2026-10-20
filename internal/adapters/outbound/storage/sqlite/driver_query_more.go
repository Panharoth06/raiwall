package sqlite

import (
	"database/sql/driver"
	"sort"
	"strings"
)

func (s *controlStmt) queryMore(st *databaseState, q string, args []driver.Value) (driver.Rows, bool) {
	// raiwall_rate_policies
	if strings.Contains(q, "FROM raiwall_rate_policies WHERE id = ?") {
		id := toStringVal(args[0])
		if pol, ok := st.ratePolicies[id]; ok {
			return &driverMemoryRows{
				columns: []string{
					"id", "name", "host", "tier1_rate", "tier1_burst", "tier1_period_sec",
					"tier2_threshold", "tier2_period_sec", "tier2_ban_duration_sec",
					"tier3_threshold", "tier3_ban_duration_sec", "waiting_room_enabled",
					"waiting_room_capacity", "waiting_room_paths", "is_active", "created_at", "updated_at",
				},
				data: [][]driver.Value{
					{
						pol.ID, pol.Name, pol.Host, pol.Tier1Rate, pol.Tier1Burst, pol.Tier1PeriodSec,
						pol.Tier2Threshold, pol.Tier2PeriodSec, pol.Tier2BanDurationSec,
						pol.Tier3Threshold, pol.Tier3BanDurationSec, pol.WaitingRoomEnabled,
						pol.WaitingRoomCapacity, pol.WaitingRoomPaths, pol.IsActive, pol.CreatedAt, pol.UpdatedAt,
					},
				},
			}, true
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_rate_policies") {
		activeOnly := strings.Contains(q, "WHERE is_active = 1")
		list := make([]*RaiwallRatePolicy, 0)
		for _, p := range st.ratePolicies {
			if activeOnly && p.IsActive != 1 {
				continue
			}
			list = append(list, p)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].CreatedAt.After(list[j].CreatedAt)
		})
		rows := make([][]driver.Value, len(list))
		for i, p := range list {
			rows[i] = []driver.Value{
				p.ID, p.Name, p.Host, p.Tier1Rate, p.Tier1Burst, p.Tier1PeriodSec,
				p.Tier2Threshold, p.Tier2PeriodSec, p.Tier2BanDurationSec,
				p.Tier3Threshold, p.Tier3BanDurationSec, p.WaitingRoomEnabled,
				p.WaitingRoomCapacity, p.WaitingRoomPaths, p.IsActive, p.CreatedAt, p.UpdatedAt,
			}
		}
		return &driverMemoryRows{
			columns: []string{
				"id", "name", "host", "tier1_rate", "tier1_burst", "tier1_period_sec",
				"tier2_threshold", "tier2_period_sec", "tier2_ban_duration_sec",
				"tier3_threshold", "tier3_ban_duration_sec", "waiting_room_enabled",
				"waiting_room_capacity", "waiting_room_paths", "is_active", "created_at", "updated_at",
			},
			data: rows,
		}, true
	}

	// raiwall_bot_configs
	if strings.Contains(q, "FROM raiwall_bot_configs WHERE id = ?") {
		id := toStringVal(args[0])
		if b, ok := st.botConfigs[id]; ok {
			return &driverMemoryRows{
				columns: []string{
					"id", "host", "pow_enabled", "pow_difficulty", "trap_urls",
					"is_active", "created_at", "updated_at",
				},
				data: [][]driver.Value{
					{b.ID, b.Host, b.PowEnabled, b.PowDifficulty, b.TrapUrls, b.IsActive, b.CreatedAt, b.UpdatedAt},
				},
			}, true
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_bot_configs") {
		activeOnly := strings.Contains(q, "WHERE is_active = 1")
		list := make([]*RaiwallBotConfig, 0)
		for _, b := range st.botConfigs {
			if activeOnly && b.IsActive != 1 {
				continue
			}
			list = append(list, b)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].CreatedAt.After(list[j].CreatedAt)
		})
		rows := make([][]driver.Value, len(list))
		for i, b := range list {
			rows[i] = []driver.Value{
				b.ID, b.Host, b.PowEnabled, b.PowDifficulty, b.TrapUrls, b.IsActive, b.CreatedAt, b.UpdatedAt,
			}
		}
		return &driverMemoryRows{
			columns: []string{
				"id", "host", "pow_enabled", "pow_difficulty", "trap_urls",
				"is_active", "created_at", "updated_at",
			},
			data: rows,
		}, true
	}

	// raiwall_config_snapshots
	if strings.Contains(q, "FROM raiwall_config_snapshots WHERE version = ?") {
		ver := toInt64Val(args[0])
		for _, snap := range st.snapshots {
			if snap.Version == ver {
				return &driverMemoryRows{
					columns: []string{"version", "snapshot_data", "author", "description", "created_at"},
					data: [][]driver.Value{
						{snap.Version, snap.SnapshotData, snap.Author, snap.Description, snap.CreatedAt},
					},
				}, true
			}
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_config_snapshots ORDER BY version DESC LIMIT 1") {
		if len(st.snapshots) > 0 {
			snap := st.snapshots[len(st.snapshots)-1]
			return &driverMemoryRows{
				columns: []string{"version", "snapshot_data", "author", "description", "created_at"},
				data: [][]driver.Value{
					{snap.Version, snap.SnapshotData, snap.Author, snap.Description, snap.CreatedAt},
				},
			}, true
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_config_snapshots ORDER BY version DESC") {
		list := make([]*RaiwallConfigSnapshot, len(st.snapshots))
		copy(list, st.snapshots)
		sort.Slice(list, func(i, j int) bool {
			return list[i].Version > list[j].Version
		})
		rows := make([][]driver.Value, len(list))
		for i, snap := range list {
			rows[i] = []driver.Value{
				snap.Version, snap.SnapshotData, snap.Author, snap.Description, snap.CreatedAt,
			}
		}
		return &driverMemoryRows{
			columns: []string{"version", "snapshot_data", "author", "description", "created_at"},
			data: rows,
		}, true
	}

	return nil, false
}
