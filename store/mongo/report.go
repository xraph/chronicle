package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"

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

	_, err = s.mdb.NewInsert(m).Exec(ctx)
	return err
}

// GetReport returns a report by ID.
func (s *Store) GetReport(ctx context.Context, reportID id.ID) (*compliance.Report, error) {
	var m ReportModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": reportID.String()}).Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, chronicle.ErrReportNotFound
		}
		return nil, fmt.Errorf("failed to get report: %w", err)
	}

	r, err := toReport(&m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert report model: %w", err)
	}

	return r, nil
}

// ListReports returns reports with pagination.
func (s *Store) ListReports(ctx context.Context, opts compliance.ListOpts) ([]*compliance.Report, error) {
	var models []ReportModel
	findQ := s.mdb.NewFind(&models).
		Filter(bson.M{}).
		Sort(bson.D{{Key: "created_at", Value: -1}})

	if opts.Limit > 0 {
		findQ = findQ.Limit(int64(opts.Limit))
	}
	if opts.Offset > 0 {
		findQ = findQ.Skip(int64(opts.Offset))
	}

	if err := findQ.Scan(ctx); err != nil {
		return nil, fmt.Errorf("failed to list reports: %w", err)
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
	res, err := s.mdb.NewDelete((*ReportModel)(nil)).
		Filter(bson.M{"_id": reportID.String()}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete report: %w", err)
	}

	if res.DeletedCount() == 0 {
		return fmt.Errorf("%w: report %s", chronicle.ErrReportNotFound, reportID)
	}

	return nil
}
