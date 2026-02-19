package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/id"
)

// SaveReport persists a generated compliance report.
func (s *Store) SaveReport(ctx context.Context, r *compliance.Report) error {
	// Marshal sections to JSON for JSONB storage
	data, err := json.Marshal(r.Sections)
	if err != nil {
		return fmt.Errorf("failed to marshal report sections: %w", err)
	}

	query := `
		INSERT INTO chronicle_reports (
			id, title, type, period_from, period_to,
			app_id, tenant_id, format, data, generated_by, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)`

	_, err = s.pool.Exec(ctx, query,
		r.ID, r.Title, r.Type, r.Period.From, r.Period.To,
		r.AppID, r.TenantID, r.Format, data, r.GeneratedBy, r.CreatedAt,
	)
	return err
}

// GetReport returns a report by ID.
func (s *Store) GetReport(ctx context.Context, reportID id.ID) (*compliance.Report, error) {
	query := `
		SELECT
			id, title, type, period_from, period_to,
			app_id, tenant_id, format, data, generated_by, created_at
		FROM chronicle_reports
		WHERE id = $1`

	r := &compliance.Report{}
	var data []byte

	err := s.pool.QueryRow(ctx, query, reportID).Scan(
		&r.ID, &r.Title, &r.Type, &r.Period.From, &r.Period.To,
		&r.AppID, &r.TenantID, &r.Format, &data, &r.GeneratedBy, &r.CreatedAt,
	)

	if err != nil {
		return nil, pgxError(err, chronicle.ErrReportNotFound)
	}

	// Unmarshal sections from JSONB
	if err := json.Unmarshal(data, &r.Sections); err != nil {
		return nil, fmt.Errorf("failed to unmarshal report sections: %w", err)
	}

	return r, nil
}

// ListReports returns reports with pagination.
func (s *Store) ListReports(ctx context.Context, opts compliance.ListOpts) ([]*compliance.Report, error) {
	query := `
		SELECT
			id, title, type, period_from, period_to,
			app_id, tenant_id, format, data, generated_by, created_at
		FROM chronicle_reports
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := s.pool.Query(ctx, query, opts.Limit, opts.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []*compliance.Report
	for rows.Next() {
		r := &compliance.Report{}
		var data []byte

		err := rows.Scan(
			&r.ID, &r.Title, &r.Type, &r.Period.From, &r.Period.To,
			&r.AppID, &r.TenantID, &r.Format, &data, &r.GeneratedBy, &r.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Unmarshal sections from JSONB
		if err := json.Unmarshal(data, &r.Sections); err != nil {
			return nil, fmt.Errorf("failed to unmarshal report sections: %w", err)
		}

		reports = append(reports, r)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return reports, nil
}

// DeleteReport removes a report by ID.
func (s *Store) DeleteReport(ctx context.Context, reportID id.ID) error {
	query := `DELETE FROM chronicle_reports WHERE id = $1`

	result, err := s.pool.Exec(ctx, query, reportID)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: report %s", chronicle.ErrReportNotFound, reportID)
	}

	return nil
}
