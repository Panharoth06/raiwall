package sqlite

import "context"

// Ping verifies the control database is reachable.
func (s *Store) Ping(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "SELECT 1")
	return err
}
