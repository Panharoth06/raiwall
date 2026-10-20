package caddy

import (
	"time"

	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/caddyserver/caddy/v2"
)

func (m *Middleware) provisionBot(_ caddy.Context) error {
	if m.PoWDifficulty <= 0 {
		m.PoWDifficulty = bot.DefaultPoWDifficulty
	}
	if m.ClearanceTTL <= 0 {
		m.ClearanceTTL = caddy.Duration(bot.DefaultClearanceTTL)
	}
	if m.HoneypotTrap == nil {
		enabled := true
		m.HoneypotTrap = &enabled
	}

	if m.botClassifier == nil {
		m.botClassifier = bot.NewBotClassifier()
	}
	if m.routeClass == nil {
		m.routeClass = bot.NewRouteClassifier(nil)
	}
	if m.powEngine == nil {
		m.powEngine = bot.NewPoWEngine(bot.PoWConfig{
			Secret:     m.PoWSecret,
			Difficulty: m.PoWDifficulty,
		})
	}
	if m.clearanceMgr == nil {
		m.clearanceMgr = bot.NewClearanceManager(bot.ClearanceConfig{
			Secret: m.powEngine.Secret(),
			TTL:    time.Duration(m.ClearanceTTL),
		}, m.powEngine)
	}
	if m.honeypotInj == nil {
		m.honeypotInj = bot.NewHoneypotInjector(bot.DefaultTrapPath)
	}

	return nil
}
