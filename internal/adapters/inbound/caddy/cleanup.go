package caddy

// Cleanup releases all background resources, closing rate limit storage, ban manager, waiting room loops, GeoIP reader, and telemetry stores.
func (m *Middleware) Cleanup() error {
	if m.ringBuffer != nil {
		_ = m.ringBuffer.Close()
	}
	if m.storageRegistry != nil {
		_ = m.storageRegistry.Close()
	} else {
		if m.telemetryStore != nil {
			_ = m.telemetryStore.Close()
		}
		if m.controlStore != nil {
			_ = m.controlStore.Close()
		}
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
	// Stop the subscriber before the client it reads from is closed. The
	// rate storage owns the shared client and closes it below.
	if m.clusterSub != nil {
		m.clusterSub.Stop()
	}
	if m.clusterStop != nil {
		close(m.clusterStop)
	}
	m.clusterWG.Wait()
	if m.rateStorage != nil {
		_ = m.rateStorage.Close()
	}
	// RedisStorage already closes the shared client; this covers a client that
	// was built for cluster sync while a different storage was injected.
	if m.redisClient != nil {
		_ = m.redisClient.Close()
	}
	if m.sidecarServer != nil {
		m.sidecarServer.Stop()
	}
	if m.upstreamRegistry != nil {
		m.upstreamRegistry.Close()
	}
	if m.discoveryCataloger != nil {
		m.discoveryCataloger.Close()
	}
	return nil
}
