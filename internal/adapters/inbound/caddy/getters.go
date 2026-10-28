package caddy

import (
	"github.com/Panharoth06/raiwall/internal/adapters/inbound/http"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/alerts"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/control/templates"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/Panharoth06/raiwall/internal/core/waf"
)

// SetEngine overrides the inspection engine (used for testing or custom engine injection).
func (m *Middleware) SetEngine(eng waf.WAFEnginePort) {
	m.engine = eng
}

// Engine returns the active inspection engine.
func (m *Middleware) Engine() waf.WAFEnginePort {
	return m.engine
}

// RunMode returns the current statically configured run mode.
func (m *Middleware) RunMode() control.RunMode {
	return m.runMode
}

// SetExceptionEngine overrides the ExceptionEngine (used for testing).
func (m *Middleware) SetExceptionEngine(ee *acl.ExceptionEngine) {
	m.exceptionEngine = ee
	if sem, ok := m.engine.(*waf.SemanticEngine); ok {
		sem.SetExceptionEngine(ee)
	}
}

// ExceptionEngine returns the configured ExceptionEngine.
func (m *Middleware) ExceptionEngine() *acl.ExceptionEngine {
	return m.exceptionEngine
}

// SetBARTTable overrides the BARTTable (used for testing).
func (m *Middleware) SetBARTTable(bt *acl.BARTTable) {
	m.bartTable = bt
	if eng := m.aclEngine.Load(); eng != nil {
		eng.SetBARTTable(bt)
	}
}

// BARTTable returns the active BARTTable.
func (m *Middleware) BARTTable() *acl.BARTTable {
	return m.bartTable
}

// SetIPGroupManager overrides the IPGroupManager (used for testing).
func (m *Middleware) SetIPGroupManager(mgr *acl.IPGroupManager) {
	m.ipGroupMgr = mgr
	if eng := m.aclEngine.Load(); eng != nil {
		eng.SetIPGroupManager(mgr)
	}
	if m.controlAPI != nil {
		m.controlAPI.SetIPGroupManager(mgr)
	}
}

// IPGroupManager returns the active IPGroupManager.
func (m *Middleware) IPGroupManager() *acl.IPGroupManager {
	if eng := m.aclEngine.Load(); eng != nil && eng.IPGroupManager() != nil {
		return eng.IPGroupManager()
	}
	return m.ipGroupMgr
}

// SetGeoIPReader overrides the GeoIPReader (used for testing).
func (m *Middleware) SetGeoIPReader(r acl.GeoIPReader) {
	m.geoIPReader = r
	if eng := m.aclEngine.Load(); eng != nil {
		eng.SetGeoIPReader(r)
	}
}

// GeoIPReader returns the active GeoIPReader.
func (m *Middleware) GeoIPReader() acl.GeoIPReader {
	return m.geoIPReader
}

// SetACLEngine sets the active ACLEngine.
func (m *Middleware) SetACLEngine(e *acl.ACLEngine) {
	m.aclEngine.Store(e)
}

// ACLEngine returns the active ACLEngine.
func (m *Middleware) ACLEngine() *acl.ACLEngine {
	return m.aclEngine.Load()
}

// SetGlobalAuthGate sets the portal-wide HTTP 467 gate built from the
// auth configuration block (also used by integration fixtures).
func (m *Middleware) SetGlobalAuthGate(g *auth.AppAuthGate) {
	m.globalAuthGate = g
}

// GlobalAuthGate returns the portal-wide HTTP 467 gate.
func (m *Middleware) GlobalAuthGate() *auth.AppAuthGate {
	return m.globalAuthGate
}

// SetBanManager sets the active BanManager.
func (m *Middleware) SetBanManager(bm *rate.BanManager) {
	m.banManager = bm
}

// BanManager returns the active BanManager.
func (m *Middleware) BanManager() *rate.BanManager {
	return m.banManager
}

// SetTier1Limiter sets the active Tier1VelocityLimiter.
func (m *Middleware) SetTier1Limiter(l *rate.Tier1VelocityLimiter) {
	m.tier1Limiter = l
}

// Tier1Limiter returns the active Tier1VelocityLimiter.
func (m *Middleware) Tier1Limiter() *rate.Tier1VelocityLimiter {
	return m.tier1Limiter
}

// SetTier2Limiter sets the active Tier2AttackLimiter.
func (m *Middleware) SetTier2Limiter(l *rate.Tier2AttackLimiter) {
	m.tier2Limiter = l
}

// Tier2Limiter returns the active Tier2AttackLimiter.
func (m *Middleware) Tier2Limiter() *rate.Tier2AttackLimiter {
	return m.tier2Limiter
}

// SetTier3Trap sets the active Tier3ScannerTrap.
func (m *Middleware) SetTier3Trap(t *rate.Tier3ScannerTrap) {
	m.tier3Trap = t
}

// Tier3Trap returns the active Tier3ScannerTrap.
func (m *Middleware) Tier3Trap() *rate.Tier3ScannerTrap {
	return m.tier3Trap
}

// SetWaitingRoom sets the active WaitingRoomManager.
func (m *Middleware) SetWaitingRoom(wm *rate.WaitingRoomManager) {
	m.waitingRoom = wm
}

// WaitingRoom returns the active WaitingRoomManager.
func (m *Middleware) WaitingRoom() *rate.WaitingRoomManager {
	return m.waitingRoom
}

// SetBotClassifier sets the active BotClassifier.
func (m *Middleware) SetBotClassifier(c *bot.BotClassifier) {
	m.botClassifier = c
}

// SetPoWEngine sets the active PoWEngine.
func (m *Middleware) SetPoWEngine(p *bot.PoWEngine) {
	m.powEngine = p
}

// SetClearanceManager sets the active ClearanceManager.
func (m *Middleware) SetClearanceManager(cm *bot.ClearanceManager) {
	m.clearanceMgr = cm
}

// SetTrapController sets the active TrapController.
func (m *Middleware) SetTrapController(tc *bot.TrapController) {
	m.trapCtrl = tc
}

// TrapController returns the active TrapController.
func (m *Middleware) TrapController() *bot.TrapController {
	return m.trapCtrl
}

// ClearanceManager returns the active ClearanceManager.
func (m *Middleware) ClearanceManager() *bot.ClearanceManager {
	return m.clearanceMgr
}

// PoWEngine returns the active PoWEngine.
func (m *Middleware) PoWEngine() *bot.PoWEngine {
	return m.powEngine
}

// SetTelemetryStore sets the persistent forensic event store.
func (m *Middleware) SetTelemetryStore(s telemetry.ForensicStore) {
	m.telemetryStore = s
	if m.telemetryAPI != nil {
		m.telemetryAPI = api.NewTelemetryAPI(s, m.streamer, m.metrics)
	}
}

// TelemetryStore returns the active ForensicStore.
func (m *Middleware) TelemetryStore() telemetry.ForensicStore {
	return m.telemetryStore
}

// SetRingBuffer sets the telemetry async ring buffer.
func (m *Middleware) SetRingBuffer(rb *telemetry.RingBuffer) {
	m.ringBuffer = rb
}

// RingBuffer returns the active ring buffer.
func (m *Middleware) RingBuffer() *telemetry.RingBuffer {
	return m.ringBuffer
}

// SetEventStreamer sets the SSE event streamer.
func (m *Middleware) SetEventStreamer(s *api.EventStreamer) {
	m.streamer = s
	if m.telemetryAPI != nil {
		m.telemetryAPI = api.NewTelemetryAPI(m.telemetryStore, s, m.metrics)
	}
}

// EventStreamer returns the active EventStreamer.
func (m *Middleware) EventStreamer() *api.EventStreamer {
	return m.streamer
}

// SetAlertEngine sets the alert notification engine.
func (m *Middleware) SetAlertEngine(ae *alerts.AlertEngine) {
	m.alertEngine = ae
}

// AlertEngine returns the active AlertEngine.
func (m *Middleware) AlertEngine() *alerts.AlertEngine {
	return m.alertEngine
}

// SetMetrics sets the Prometheus metrics registry wrapper.
func (m *Middleware) SetMetrics(met *telemetry.Metrics) {
	m.metrics = met
	if m.telemetryAPI != nil {
		m.telemetryAPI = api.NewTelemetryAPI(m.telemetryStore, m.streamer, met)
	}
}

// Metrics returns the active Metrics instance.
func (m *Middleware) Metrics() *telemetry.Metrics {
	return m.metrics
}

// SetUIHandler sets the UI handler instance.
func (m *Middleware) SetUIHandler(ui *UIHandler) {
	m.uiHandler = ui
}

// UIHandler returns the active UIHandler.
func (m *Middleware) UIHandler() *UIHandler {
	return m.uiHandler
}

// SetTelemetryAPI sets the telemetry HTTP API handler.
func (m *Middleware) SetTelemetryAPI(api *api.TelemetryAPI) {
	m.telemetryAPI = api
}

// TelemetryAPI returns the active TelemetryAPI.
func (m *Middleware) TelemetryAPI() *api.TelemetryAPI {
	return m.telemetryAPI
}

// SetControlAPI sets the Control Plane REST API server.
func (m *Middleware) SetControlAPI(srv *api.Server) {
	m.controlAPI = srv
}

// ControlAPI returns the active Control Plane REST API server.
func (m *Middleware) ControlAPI() *api.Server {
	return m.controlAPI
}

// SetUpstreamRegistry sets the active UpstreamRegistry.
func (m *Middleware) SetUpstreamRegistry(ur *UpstreamRegistry) {
	m.upstreamRegistry = ur
}

// UpstreamRegistry returns the active UpstreamRegistry.
func (m *Middleware) UpstreamRegistry() *UpstreamRegistry {
	return m.upstreamRegistry
}

// SetDiscoveryCataloger sets the active APIDiscoveryCataloger.
func (m *Middleware) SetDiscoveryCataloger(dc *APIDiscoveryCataloger) {
	m.discoveryCataloger = dc
}

// DiscoveryCataloger returns the active APIDiscoveryCataloger.
func (m *Middleware) DiscoveryCataloger() *APIDiscoveryCataloger {
	return m.discoveryCataloger
}

// SetTemplateManager sets the active TemplateManager.
func (m *Middleware) SetTemplateManager(mgr *templates.TemplateManager) {
	m.templateManager = mgr
}

// TemplateManager returns the active TemplateManager.
func (m *Middleware) TemplateManager() *templates.TemplateManager {
	return m.templateManager
}
