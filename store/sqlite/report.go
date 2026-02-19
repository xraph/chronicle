package sqlite

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
	// Marshal sections to JSON for TEXT storage.
	data, err := json.Marshal(r.Sections)
	if err != nil {
		return fmt.Errorf("failed to marshal report sections: %w", err)
	}

	query := `
		INSERT INTO chronicle_reports (
			id, title, type, period_from, period_to,
			app_id, tenant_id, format, data, generated_by, created_at
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		)`

	_, err = s.db.ExecContext(ctx, query,
		r.ID.String(), r.Title, r.Type,
		formatTime(r.Period.From), formatTime(r.Period.To),
		r.AppID, r.TenantID, string(r.Format), string(data),
		r.GeneratedBy, formatTime(r.CreatedAt),
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
		WHERE id = ?`

	r := &compliance.Report{}
	var (
		idStr      string
		periodFrom string
		periodTo   string
		format     string
		data       string
		createdAt  string
	)

	err := s.db.QueryRowContext(ctx, query, reportID.String()).Scan(
		&idStr, &r.Title, &r.Type, &periodFrom, &periodTo,
		&r.AppID, &r.TenantID, &format, &data, &r.GeneratedBy, &createdAt,
	)
	if err != nil {
		return nil, sqliteError(err, chronicle.ErrReportNotFound)
	}

	parsedID, err := id.ParseReportID(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse report ID %q: %w", idStr, err)
	}
	r.ID = parsedID
	r.Format = compliance.Format(format)

	r.Period.From, err = parseTime(periodFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to parse period_from: %w", err)
	}

	r.Period.To, err = parseTime(periodTo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse period_to: %w", err)
	}

	r.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	// Unmarshal sections from JSON.
	if err := json.Unmarshal([]byte(data), &r.Sections); err != nil {
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
		LIMIT ? OFFSET ?`

	rows, err := s.db.QueryContext(ctx, query, opts.Limit, opts.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list reports: %w", err)
	}
	defer rows.Close()

	var reports []*compliance.Report
	for rows.Next() {
		r := &compliance.Report{}
		var (
			idStr      string
			periodFrom string
			periodTo   string
			format     string
			data       string
			createdAt  string
		)

		err := rows.Scan(
			&idStr, &r.Title, &r.Type, &periodFrom, &periodTo,
			&r.AppID, &r.TenantID, &format, &data, &r.GeneratedBy, &createdAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan report row: %w", err)
		}

		parsedID, err := id.ParseReportID(idStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse report ID %q: %w", idStr, err)
		}
		r.ID = parsedID
		r.Format = compliance.Format(format)

		r.Period.From, err = parseTime(periodFrom)
		if err != nil {
			return nil, fmt.Errorf("failed to parse period_from: %w", err)
		}

		r.Period.To, err = parseTime(periodTo)
		if err != nil {
			return nil, fmt.Errorf("failed to parse period_to: %w", err)
		}

		r.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created_at: %w", err)
		}

		// Unmarshal sections from JSON.
		if err := json.Unmarshal([]byte(data), &r.Sections); err != nil {
			return nil, fmt.Errorf("failed to unmarshal report sections: %w", err)
		}

		reports = append(reports, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate report rows: %w", err)
	}

	return reports, nil
}

// DeleteReport removes a report by ID.
func (s *Store) DeleteReport(ctx context.Context, reportID id.ID) error {
	query := `DELETE FROM chronicle_reports WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query, reportID.String())
	if err != nil {
		return fmt.Errorf("failed to delete report: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if n == 0 {
		return fmt.Errorf("%w: report %s", chronicle.ErrReportNotFound, reportID)
	}

	return nil
}
