package sqlite

import "context"

// Ping verifies the control database is reachable.
func (s *Store) Ping(ctx context.Context) error {
	_, err := s.conn().ExecContext(ctx, "SELECT 1")
	return err
}
