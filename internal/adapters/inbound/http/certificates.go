package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/control/declarative"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// CertificateDTO is the API representation of a managed certificate. Private
// key material is never exposed.
type CertificateDTO struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Domains           []string  `json:"domains"`
	Source            string    `json:"source"`
	CertificatePEM    string    `json:"cert_pem,omitempty"`
	FingerprintSHA256 string    `json:"fingerprint_sha256,omitempty"`
	Issuer            string    `json:"issuer,omitempty"`
	NotBefore         time.Time `json:"not_before,omitempty"`
	NotAfter          time.Time `json:"not_after,omitempty"`
	AutoRenew         bool      `json:"auto_renew"`
	LastError         string    `json:"last_error,omitempty"`
	Status            string    `json:"status"`
	Managed           bool      `json:"managed"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// CertificateRequest is the create/update payload for managed certificates.
type CertificateRequest struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	Source    string   `json:"source"`
	CertPEM   string   `json:"cert_pem"`
	KeyPEM    string   `json:"key_pem"`
	AutoRenew *bool    `json:"auto_renew"`
}

func certificateDTO(rec control.CertificateRecord, now time.Time) CertificateDTO {
	var domains []string
	_ = json.Unmarshal([]byte(rec.Domains), &domains)
	status := "valid"
	switch {
	case rec.Source == control.CertSourceACME && rec.CertPEM == "":
		status = "pending"
	case !rec.NotAfter.IsZero() && now.After(rec.NotAfter):
		status = "expired"
	case !rec.NotAfter.IsZero() && rec.NotAfter.Before(now.Add(expiringWindow)):
		status = "expiring"
	}
	return CertificateDTO{
		ID:                rec.ID,
		Name:              rec.Name,
		Domains:           domains,
		Source:            rec.Source,
		CertificatePEM:    rec.CertPEM,
		FingerprintSHA256: rec.FingerprintSHA256,
		Issuer:            rec.Issuer,
		NotBefore:         rec.NotBefore,
		NotAfter:          rec.NotAfter,
		AutoRenew:         rec.AutoRenew == 1,
		LastError:         rec.LastError,
		Status:            status,
		Managed:           declarative.IsManaged(rec.ID),
		CreatedAt:         rec.CreatedAt,
		UpdatedAt:         rec.UpdatedAt,
	}
}

func (s *Server) handleListCertificates(w http.ResponseWriter, r *http.Request) {
	records, err := s.store.ListCertificates(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list certificates: "+err.Error())
		return
	}
	now := time.Now().UTC()
	out := make([]CertificateDTO, 0, len(records))
	for _, rec := range records {
		out = append(out, certificateDTO(rec, now))
	}
	respondJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	rec, err := s.store.GetCertificate(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusNotFound, "certificate not found")
		return
	}
	respondJSON(w, http.StatusOK, certificateDTO(rec, time.Now().UTC()))
}

func (s *Server) handleCreateCertificate(w http.ResponseWriter, r *http.Request) {
	var req CertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	record, err := s.buildCertificate(r.Context(), req, time.Now().UTC())
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateCertificate(r.Context(), record); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create certificate: "+err.Error())
		return
	}
	s.reloadCertificates(r.Context())
	respondJSON(w, http.StatusCreated, certificateDTO(record, time.Now().UTC()))
}

func (s *Server) handleUpdateCertificate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := s.store.GetCertificate(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "certificate not found")
		return
	}

	var req CertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	// Source and key material are immutable through update; use renew or re-upload.
	req.Source = existing.Source
	req.CertPEM = ""
	req.KeyPEM = ""
	if strings.TrimSpace(req.Name) == "" {
		req.Name = existing.Name
	}
	if len(req.Domains) == 0 {
		_ = json.Unmarshal([]byte(existing.Domains), &req.Domains)
	}

	domains, err := normalizeCertDomains(req.Domains)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	domainsJSON, _ := json.Marshal(domains)
	existing.Name = req.Name
	existing.Domains = string(domainsJSON)
	existing.AutoRenew = boolToInt64(req.AutoRenew == nil || *req.AutoRenew)
	existing.UpdatedAt = time.Now().UTC()
	if existing.Source == control.CertSourceACME {
		existing.LastError = ""
	}

	if err := s.store.UpdateCertificate(r.Context(), existing); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update certificate: "+err.Error())
		return
	}
	s.reloadCertificates(r.Context())
	respondJSON(w, http.StatusOK, certificateDTO(existing, time.Now().UTC()))
}

func (s *Server) handleDeleteCertificate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := s.store.GetCertificate(r.Context(), id); err != nil {
		respondError(w, http.StatusNotFound, "certificate not found")
		return
	}

	inUseBy, checkErr := s.certificateInUse(r.Context(), id)
	if checkErr != nil {
		respondError(w, http.StatusInternalServerError, "failed to verify certificate usage: "+checkErr.Error())
		return
	}
	if inUseBy != "" {
		respondError(w, http.StatusConflict, fmt.Sprintf("certificate is in use by site %q", inUseBy))
		return
	}

	if err := s.store.DeleteCertificate(r.Context(), id); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete certificate: "+err.Error())
		return
	}
	s.reloadCertificates(r.Context())
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}

func (s *Server) handleRenewCertificate(w http.ResponseWriter, r *http.Request) {
	rec, err := s.store.GetCertificate(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusNotFound, "certificate not found")
		return
	}
	if rec.Source == control.CertSourceUpload {
		respondError(w, http.StatusBadRequest, "uploaded certificates cannot be renewed; upload a new certificate")
		return
	}

	updated, err := s.renewCertificate(r.Context(), rec)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, certificateDTO(updated, time.Now().UTC()))
}

// renewCertificate regenerates self-signed material or re-triggers ACME issuance.
func (s *Server) renewCertificate(ctx context.Context, rec control.CertificateRecord) (control.CertificateRecord, error) {
	if rec.Source == control.CertSourceACME {
		rec.LastError = ""
		rec.UpdatedAt = time.Now().UTC()
		if err := s.store.UpdateCertificate(ctx, rec); err != nil {
			return rec, err
		}
		if s.certReconciler != nil {
			go s.certReconciler(context.Background())
		}
		return rec, nil
	}

	var domains []string
	_ = json.Unmarshal([]byte(rec.Domains), &domains)
	certPEM, keyPEM, leaf, err := control.GenerateSelfSigned(domains, time.Now().UTC())
	if err != nil {
		return rec, err
	}
	secret, err := control.EnsureCertificateSecret(ctx, s.store)
	if err != nil {
		return rec, err
	}
	encrypted, err := control.EncryptPrivateKey(secret, keyPEM)
	if err != nil {
		return rec, err
	}
	rec.CertPEM = certPEM
	rec.EncryptedKeyPEM = encrypted
	rec.FingerprintSHA256 = control.FingerprintSHA256(leaf.Raw)
	rec.Issuer = leaf.Issuer.CommonName
	rec.NotBefore = leaf.NotBefore
	rec.NotAfter = leaf.NotAfter
	rec.LastError = ""
	rec.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateCertificate(ctx, rec); err != nil {
		return rec, err
	}
	s.reloadCertificates(ctx)
	return rec, nil
}

func (s *Server) handleDownloadCertificate(w http.ResponseWriter, r *http.Request) {
	rec, err := s.store.GetCertificate(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusNotFound, "certificate not found")
		return
	}
	if rec.CertPEM == "" {
		respondError(w, http.StatusNotFound, "certificate has no downloadable PEM material")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", rec.ID+".pem"))
	_, _ = w.Write([]byte(rec.CertPEM))
}

// buildCertificate validates a create request and produces the stored record.
func (s *Server) buildCertificate(ctx context.Context, req CertificateRequest, now time.Time) (control.CertificateRecord, error) {
	source := strings.ToLower(strings.TrimSpace(req.Source))
	if source == "" {
		source = control.CertSourceSelfSigned
	}
	switch source {
	case control.CertSourceUpload, control.CertSourceSelfSigned, control.CertSourceACME:
	default:
		return control.CertificateRecord{}, fmt.Errorf("invalid certificate source %q (expected upload, self_signed, or acme)", req.Source)
	}

	domains, err := normalizeCertDomains(req.Domains)
	if err != nil {
		return control.CertificateRecord{}, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = domains[0]
	}

	record := control.CertificateRecord{
		ID:        "cert-" + uuid.New().String()[:8],
		Name:      name,
		Source:    source,
		AutoRenew: boolToInt64(req.AutoRenew == nil || *req.AutoRenew),
		CreatedAt: now,
		UpdatedAt: now,
	}
	domainsJSON, _ := json.Marshal(domains)
	record.Domains = string(domainsJSON)

	switch source {
	case control.CertSourceUpload:
		if strings.TrimSpace(req.CertPEM) == "" || strings.TrimSpace(req.KeyPEM) == "" {
			return control.CertificateRecord{}, fmt.Errorf("uploaded certificates require both cert_pem and key_pem")
		}
		leaf, err := control.ValidateCertificateKeyPair(req.CertPEM, req.KeyPEM)
		if err != nil {
			return control.CertificateRecord{}, err
		}
		if now.After(leaf.NotAfter) {
			return control.CertificateRecord{}, fmt.Errorf("certificate expired on %s", leaf.NotAfter.Format(time.RFC3339))
		}
		secret, err := control.EnsureCertificateSecret(ctx, s.store)
		if err != nil {
			return control.CertificateRecord{}, err
		}
		encrypted, err := control.EncryptPrivateKey(secret, req.KeyPEM)
		if err != nil {
			return control.CertificateRecord{}, err
		}
		record.CertPEM = req.CertPEM
		record.EncryptedKeyPEM = encrypted
		record.FingerprintSHA256 = control.FingerprintSHA256(leaf.Raw)
		record.Issuer = leaf.Issuer.CommonName
		record.NotBefore = leaf.NotBefore
		record.NotAfter = leaf.NotAfter
	case control.CertSourceSelfSigned:
		certPEM, keyPEM, leaf, err := control.GenerateSelfSigned(domains, now)
		if err != nil {
			return control.CertificateRecord{}, err
		}
		secret, err := control.EnsureCertificateSecret(ctx, s.store)
		if err != nil {
			return control.CertificateRecord{}, err
		}
		encrypted, err := control.EncryptPrivateKey(secret, keyPEM)
		if err != nil {
			return control.CertificateRecord{}, err
		}
		record.CertPEM = certPEM
		record.EncryptedKeyPEM = encrypted
		record.FingerprintSHA256 = control.FingerprintSHA256(leaf.Raw)
		record.Issuer = leaf.Issuer.CommonName
		record.NotBefore = leaf.NotBefore
		record.NotAfter = leaf.NotAfter
	case control.CertSourceACME:
		// Issued on the next apply through Caddy's ACME automation.
	}
	return record, nil
}

func normalizeCertDomains(domains []string) ([]string, error) {
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		clean := strings.ToLower(strings.TrimSpace(domain))
		if clean == "" {
			continue
		}
		if strings.ContainsAny(clean, "/ :") {
			return nil, fmt.Errorf("invalid domain %q", domain)
		}
		out = append(out, clean)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}
	return out, nil
}

// registerCertificateRoutes mounts the certificate CRUD surface at base.
func registerCertificateRoutes(r chi.Router, base string, s *Server) {
	r.Get(base, s.handleListCertificates)
	r.Post(base, s.handleCreateCertificate)
	r.Get(base+"/{id}", s.handleGetCertificate)
	r.Put(base+"/{id}", s.handleUpdateCertificate)
	r.Delete(base+"/{id}", s.handleDeleteCertificate)
	r.Post(base+"/{id}/renew", s.handleRenewCertificate)
	r.Get(base+"/{id}/download", s.handleDownloadCertificate)
}

// expiringWindow is how close to expiry a certificate must be before the API
// flags it as expiring (renewal runs at the same horizon).
const expiringWindow = 14 * 24 * time.Hour

// certificateInUse reports the name of the first site that either references
// the certificate directly or serves a hostname covered by it.
func (s *Server) certificateInUse(ctx context.Context, certID string) (string, error) {
	apps, err := s.store.ListApps(ctx)
	if err != nil {
		return "", err
	}
	var leaf *x509.Certificate
	if rec, getErr := s.store.GetCertificate(ctx, certID); getErr == nil {
		leaf, _ = control.ParseLeafCertificate(rec.CertPEM)
	}

	for _, app := range apps {
		if app.CertificateID == certID {
			return app.Name, nil
		}
		if app.SSLMode == control.SSLModeNone || leaf == nil {
			continue
		}
		var hostnames []string
		if err := json.Unmarshal([]byte(app.Hostnames), &hostnames); err != nil {
			continue
		}
		for _, host := range hostnames {
			if control.CertificateCoversDomain(leaf, strings.TrimSpace(host)) {
				return app.Name, nil
			}
		}
	}
	return "", nil
}
