package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/id"
)

// SaveReport persists a generated compliance report.
func (s *Store) SaveReport(ctx context.Context, r *compliance.Report) error {
	m, err := fromReport(r)
	if err != nil {
		return err
	}

	_, err = s.pg.NewInsert(m).Exec(ctx)
	return err
}

// GetReport returns a report by ID.
func (s *Store) GetReport(ctx context.Context, reportID id.ID) (*compliance.Report, error) {
	m := new(ReportModel)
	err := s.pg.NewSelect(m).Where("id = $1", reportID.String()).Scan(ctx)
	if err != nil {
		return nil, groveError(err, chronicle.ErrReportNotFound)
	}

	r, err := toReport(m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert report model: %w", err)
	}

	return r, nil
}

// ListReports returns reports with pagination.
func (s *Store) ListReports(ctx context.Context, opts compliance.ListOpts) ([]*compliance.Report, error) {
	var models []ReportModel
	err := s.pg.NewSelect(&models).
		OrderExpr("r.created_at DESC").
		Limit(opts.Limit).
		Offset(opts.Offset).
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	reports := make([]*compliance.Report, 0, len(models))
	for i := range models {
		r, err := toReport(&models[i])
		if err != nil {
			return nil, err
		}
		reports = append(reports, r)
	}

	return reports, nil
}

// DeleteReport removes a report by ID.
func (s *Store) DeleteReport(ctx context.Context, reportID id.ID) error {
	result, err := s.pg.NewDelete((*ReportModel)(nil)).
		Where("id = $1", reportID.String()).
		Exec(ctx)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return fmt.Errorf("%w: report %s", chronicle.ErrReportNotFound, reportID)
	}

	return nil
}
