package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/id"
)

// reportModel is the JSON representation stored in Redis.
type reportModel struct {
	ID          string               `json:"id"`
	Title       string               `json:"title"`
	Type        string               `json:"type"`
	PeriodFrom  time.Time            `json:"period_from"`
	PeriodTo    time.Time            `json:"period_to"`
	AppID       string               `json:"app_id"`
	TenantID    string               `json:"tenant_id"`
	Format      string               `json:"format"`
	Sections    []compliance.Section `json:"sections"`
	GeneratedBy string               `json:"generated_by"`
	CreatedAt   time.Time            `json:"created_at"`
}

func toReportModel(r *compliance.Report) *reportModel {
	return &reportModel{
		ID:          r.ID.String(),
		Title:       r.Title,
		Type:        r.Type,
		PeriodFrom:  r.Period.From,
		PeriodTo:    r.Period.To,
		AppID:       r.AppID,
		TenantID:    r.TenantID,
		Format:      string(r.Format),
		Sections:    r.Sections,
		GeneratedBy: r.GeneratedBy,
		CreatedAt:   r.CreatedAt,
	}
}

func fromReportModel(m *reportModel) (*compliance.Report, error) {
	reportID, err := id.ParseReportID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse report ID %q: %w", m.ID, err)
	}
	return &compliance.Report{
		Entity: chronicle.Entity{
			CreatedAt: m.CreatedAt,
		},
		ID:    reportID,
		Title: m.Title,
		Type:  m.Type,
		Period: compliance.DateRange{
			From: m.PeriodFrom,
			To:   m.PeriodTo,
		},
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Format:      compliance.Format(m.Format),
		Sections:    m.Sections,
		GeneratedBy: m.GeneratedBy,
	}, nil
}

// SaveReport persists a generated compliance report.
func (s *Store) SaveReport(ctx context.Context, r *compliance.Report) error {
	m := toReportModel(r)
	key := entityKey(prefixReport, m.ID)

	if err := s.setEntity(ctx, key, m); err != nil {
		return fmt.Errorf("chronicle/redis: save report: %w", err)
	}

	s.rdb.ZAdd(ctx, zReportAll, goredis.Z{Score: scoreFromTime(m.CreatedAt), Member: m.ID})
	return nil
}

// GetReport returns a report by ID.
func (s *Store) GetReport(ctx context.Context, reportID id.ID) (*compliance.Report, error) {
	var m reportModel
	if err := s.getEntity(ctx, entityKey(prefixReport, reportID.String()), &m); err != nil {
		if isNotFound(err) {
			return nil, chronicle.ErrReportNotFound
		}
		return nil, fmt.Errorf("chronicle/redis: get report: %w", err)
	}
	return fromReportModel(&m)
}

// ListReports returns reports with pagination.
func (s *Store) ListReports(ctx context.Context, opts compliance.ListOpts) ([]*compliance.Report, error) {
	ids, err := s.rdb.ZRevRange(ctx, zReportAll, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: list reports: %w", err)
	}

	result := make([]*compliance.Report, 0, len(ids))
	for _, entryID := range ids {
		var m reportModel
		if err := s.getEntity(ctx, entityKey(prefixReport, entryID), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		r, err := fromReportModel(&m)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}

	return applyPagination(result, opts.Offset, opts.Limit), nil
}

// DeleteReport removes a report by ID.
func (s *Store) DeleteReport(ctx context.Context, reportID id.ID) error {
	key := entityKey(prefixReport, reportID.String())

	var m reportModel
	if err := s.getEntity(ctx, key, &m); err != nil {
		if isNotFound(err) {
			return fmt.Errorf("%w: report %s", chronicle.ErrReportNotFound, reportID)
		}
		return fmt.Errorf("chronicle/redis: delete report get: %w", err)
	}

	if err := s.kv.Delete(ctx, key); err != nil {
		return fmt.Errorf("chronicle/redis: delete report: %w", err)
	}

	s.rdb.ZRem(ctx, zReportAll, m.ID)
	return nil
}

// ensure json import is used
var _ = json.Marshal
