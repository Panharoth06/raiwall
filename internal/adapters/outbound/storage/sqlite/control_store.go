package sqlite

import (
	"context"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

var _ control.ControlStore = (*Store)(nil)

// Apps

func (s *Store) ListApps(ctx context.Context) ([]control.SiteApp, error) {
	rows, err := s.Queries.ListApps(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.SiteApp, len(rows))
	for i, r := range rows {
		res[i] = toControlSiteApp(r)
	}
	return res, nil
}

func (s *Store) GetApp(ctx context.Context, id string) (control.SiteApp, error) {
	r, err := s.Queries.GetApp(ctx, id)
	if err != nil {
		return control.SiteApp{}, err
	}
	return toControlSiteApp(r), nil
}

func (s *Store) CreateApp(ctx context.Context, app control.SiteApp) error {
	return s.Queries.CreateApp(ctx, CreateAppParams{
		ID:                  app.ID,
		Name:                app.Name,
		Hostnames:           app.Hostnames,
		Mode:                app.Mode,
		Upstreams:           app.Upstreams,
		BlockStatusCode:     app.BlockStatusCode,
		BlockResponseBody:   app.BlockResponseBody,
		OfflineStatusCode:   app.OfflineStatusCode,
		OfflineResponseBody: app.OfflineResponseBody,
		CustomHeaders:       app.CustomHeaders,
		ProxySettings:       app.ProxySettings,
		CreatedAt:           app.CreatedAt,
		UpdatedAt:           app.UpdatedAt,
	})
}

func (s *Store) UpdateApp(ctx context.Context, app control.SiteApp) error {
	return s.Queries.UpdateApp(ctx, UpdateAppParams{
		ID:                  app.ID,
		Name:                app.Name,
		Hostnames:           app.Hostnames,
		Mode:                app.Mode,
		Upstreams:           app.Upstreams,
		BlockStatusCode:     app.BlockStatusCode,
		BlockResponseBody:   app.BlockResponseBody,
		OfflineStatusCode:   app.OfflineStatusCode,
		OfflineResponseBody: app.OfflineResponseBody,
		CustomHeaders:       app.CustomHeaders,
		ProxySettings:       app.ProxySettings,
		UpdatedAt:           app.UpdatedAt,
	})
}

func (s *Store) DeleteApp(ctx context.Context, id string) error {
	return s.Queries.DeleteApp(ctx, id)
}

// Exceptions

func (s *Store) ListExceptions(ctx context.Context) ([]control.ExceptionRule, error) {
	rows, err := s.Queries.ListExceptions(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.ExceptionRule, len(rows))
	for i, r := range rows {
		res[i] = toControlExceptionRule(r)
	}
	return res, nil
}

func (s *Store) ListActiveExceptions(ctx context.Context) ([]control.ExceptionRule, error) {
	rows, err := s.Queries.ListActiveExceptions(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.ExceptionRule, len(rows))
	for i, r := range rows {
		res[i] = toControlExceptionRule(r)
	}
	return res, nil
}

func (s *Store) GetException(ctx context.Context, id string) (control.ExceptionRule, error) {
	r, err := s.Queries.GetException(ctx, id)
	if err != nil {
		return control.ExceptionRule{}, err
	}
	return toControlExceptionRule(r), nil
}

func (s *Store) CreateException(ctx context.Context, exc control.ExceptionRule) error {
	return s.Queries.CreateException(ctx, CreateExceptionParams{
		ID:          exc.ID,
		Description: exc.Description,
		Host:        exc.Host,
		PathRegex:   exc.PathRegex,
		PathPrefix:  exc.PathPrefix,
		Method:      exc.Method,
		Location:    exc.Location,
		ParamName:   exc.ParamName,
		ParamRegex:  exc.ParamRegex,
		RuleID:      exc.RuleID,
		IsActive:    exc.IsActive,
		CreatedAt:   exc.CreatedAt,
		UpdatedAt:   exc.UpdatedAt,
	})
}

func (s *Store) UpdateException(ctx context.Context, exc control.ExceptionRule) error {
	return s.Queries.UpdateException(ctx, UpdateExceptionParams{
		ID:          exc.ID,
		Description: exc.Description,
		Host:        exc.Host,
		PathRegex:   exc.PathRegex,
		PathPrefix:  exc.PathPrefix,
		Method:      exc.Method,
		Location:    exc.Location,
		ParamName:   exc.ParamName,
		ParamRegex:  exc.ParamRegex,
		RuleID:      exc.RuleID,
		IsActive:    exc.IsActive,
		UpdatedAt:   exc.UpdatedAt,
	})
}

func (s *Store) DeleteException(ctx context.Context, id string) error {
	return s.Queries.DeleteException(ctx, id)
}
