package caddy

import (
	"net"
	"net/http"

	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/rate"
)

// handleWaitingRoom checks virtual waiting room admission and returns a lease release func, or handles the queue response.
func (m *Middleware) handleWaitingRoom(w http.ResponseWriter, r *http.Request, clientIP net.IP, ja4 string) (func(), bool, error) {
	if m.waitingRoom == nil {
		return nil, false, nil
	}

	snap := control.LoadSnapshot()
	if snap != nil {
		if rp, found := snap.GetRatePolicyForHost(r.Host); found && rp != nil {
			if !rp.WaitingRoomEnabled {
				return nil, false, nil
			}
			if len(rp.WaitingRoomPaths) > 0 {
				matched := false
				for _, p := range rp.WaitingRoomPaths {
					if rate.MatchesWaitingRoomPathPrefix(r.URL.Path, p) {
						matched = true
						break
					}
				}
				if !matched {
					return nil, false, nil
				}
			}
		} else if !m.waitingRoom.MatchesPath(r.URL.Path) {
			return nil, false, nil
		}
	} else if !m.waitingRoom.MatchesPath(r.URL.Path) {
		return nil, false, nil
	}

	if !m.waitingRoom.IsAdmitted(r, clientIP, ja4) {
		// Check if client is already waiting in queue (e.g. on page refresh)
		if qCookie, err := r.Cookie(rate.WaitingRoomQueueCookie); err == nil && qCookie.Value != "" {
			if pos, waitSecs, admitted, _ := m.waitingRoom.FindActiveEntry(qCookie.Value); pos > 0 || admitted {
				if !admitted {
					return nil, true, rate.RenderWaitingRoomPage(w, qCookie.Value, pos, waitSecs, r.URL.RequestURI())
				}
				// Client has been admitted from queue: grant clearance cookie and proceed
				token := m.waitingRoom.GenerateAdmissionToken(clientIP, ja4, 0)
				http.SetCookie(w, &http.Cookie{
					Name:     rate.WaitingRoomClearanceCookie,
					Value:    token,
					Path:     "/",
					SameSite: http.SameSiteLaxMode,
					HttpOnly: true,
				})
				m.waitingRoom.RemoveEntry(qCookie.Value)
				release := m.waitingRoom.AcquireLease()
				return release, false, nil
			}
		}

		if m.waitingRoom.ShouldEnterWaitingRoom() {
			if m.routeClass == nil {
				m.routeClass = bot.NewRouteClassifier(nil)
			}
			route := m.routeClass.Classify(r)
			if route == bot.RouteAPI || bot.ShouldBypassChallenge(route) {
				rate.WriteWaitingRoomOverloadedJSON(w, 30)
				return nil, true, nil
			}
			entry, pos, waitSecs, err := m.waitingRoom.Enqueue(clientIP, ja4)
			if err != nil {
				rate.WriteWaitingRoomOverloadedJSON(w, 30)
				return nil, true, nil
			}
			return nil, true, rate.RenderWaitingRoomPage(w, entry.ID, pos, waitSecs, r.URL.RequestURI())
		}
	}

	release := m.waitingRoom.AcquireLease()
	return release, false, nil
}

// enforceTier1 enforces the Tier 1 access velocity token bucket.
func (m *Middleware) enforceTier1(w http.ResponseWriter, r *http.Request, clientIP net.IP, ja4 string) (bool, error) {
	if m.tier1Limiter == nil {
		return true, nil
	}
	return m.tier1Limiter.Enforce(w, r, clientIP, ja4)
}
