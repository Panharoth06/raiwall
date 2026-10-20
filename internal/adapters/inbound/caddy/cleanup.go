package caddy

// Cleanup releases all background resources, closing rate limit storage, ban manager, waiting room loops, GeoIP reader, and telemetry stores.
func (m *Middleware) Cleanup() error {
	if m.ringBuffer != nil {
		_ = m.ringBuffer.Close()
	}
	if m.telemetryStore != nil {
		_ = m.telemetryStore.Close()
	}
	if m.geoIPReader != nil {
		_ = m.geoIPReader.Close()
	}
	if m.waitingRoom != nil {
		_ = m.waitingRoom.Close()
	}
	if m.banManager != nil {
		_ = m.banManager.Close()
	}
	if m.rateStorage != nil {
		_ = m.rateStorage.Close()
	}
	if m.sidecarServer != nil {
		m.sidecarServer.Stop()
	}
	if m.controlStore != nil {
		_ = m.controlStore.Close()
	}
	if m.upstreamRegistry != nil {
		m.upstreamRegistry.Close()
	}
	if m.discoveryCataloger != nil {
		m.discoveryCataloger.Close()
	}
	return nil
}
