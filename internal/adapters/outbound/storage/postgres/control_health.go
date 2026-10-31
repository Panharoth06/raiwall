package postgres

import "context"

// Ping verifies the control database is reachable.
func (s *ControlStore) Ping(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "SELECT 1")
	return err
}
