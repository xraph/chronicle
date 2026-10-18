package telemetry

import (
	"time"

	gometrics "github.com/xraph/go-utils/metrics"
)

// Metric names as Chronicle registers them. A Forge app exports each one with
// its namespace prefix, so chronicle_events_recorded_total scrapes as
// forge_chronicle_events_recorded_total.
const (
	MetricEventsRecorded       = "chronicle_events_recorded_total"
	MetricRecordDuration       = "chronicle_record_duration_seconds"
	MetricEventsArchived       = "chronicle_events_archived_total"
	MetricEventsPurged         = "chronicle_events_purged_total"
	MetricCheckpointsAttempted = "chronicle_checkpoints_attempted_total"
	MetricSchedulerRunDuration = "chronicle_scheduler_run_duration_seconds"
)

// Label keys.
const (
	LabelOperation = "operation"
	LabelResult    = "result"
	LabelJob       = "job"
)

// Label values. These are the only values any label ever takes.
const (
	OperationRecord     = "record"
	OperationRecordOnce = "record_once"

	ResultOK         = "ok"
	ResultError      = "error"
	ResultNothingNew = "nothing_new"
	ResultLostRace   = "lost_race"

	JobRetention  = "retention"
	JobCheckpoint = "checkpoint"
)

// RecordBuckets are the bounds, in seconds, for MetricRecordDuration. A
// record is a stream lock, a digest and two or three queries, so the
// interesting range is sub-millisecond to a few seconds under contention.
var RecordBuckets = []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

// SchedulerBuckets are the bounds, in seconds, for MetricSchedulerRunDuration.
// A run covers every policy or every stream, so it can take minutes.
var SchedulerBuckets = []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300, 900}

// Result is the result label for a call that either worked or did not.
func Result(err error) string {
	if err != nil {
		return ResultError
	}
	return ResultOK
}

type opResult struct{ op, result string }

// RecordMetrics is what Chronicle.Record and Chronicle.RecordOnce record on.
// A nil *RecordMetrics records nothing.
type RecordMetrics struct {
	recorded map[opResult]gometrics.Counter
	duration map[opResult]gometrics.Histogram
}

// NewRecordMetrics registers every record series on m up front, so a call
// never creates one. A nil m returns nil.
func NewRecordMetrics(m gometrics.Metrics) *RecordMetrics {
	if m == nil {
		return nil
	}
	r := &RecordMetrics{
		recorded: make(map[opResult]gometrics.Counter, 4),
		duration: make(map[opResult]gometrics.Histogram, 4),
	}
	for _, op := range []string{OperationRecord, OperationRecordOnce} {
		for _, res := range []string{ResultOK, ResultError} {
			k := opResult{op, res}
			r.recorded[k] = m.Counter(MetricEventsRecorded,
				gometrics.WithDescription("Audit events Chronicle was asked to record, by entry point and result."),
				gometrics.WithLabels(map[string]string{LabelOperation: op, LabelResult: res}),
			)
			r.duration[k] = m.Histogram(MetricRecordDuration,
				gometrics.WithDescription("Time to link one audit event into its hash chain and store it."),
				gometrics.WithUnit("s"),
				gometrics.WithBuckets(RecordBuckets...),
				gometrics.WithLabels(map[string]string{LabelOperation: op, LabelResult: res}),
			)
		}
	}
	return r
}

// Observe records one call to operation that took elapsed and ended in err.
func (r *RecordMetrics) Observe(operation string, err error, elapsed time.Duration) {
	if r == nil {
		return
	}
	k := opResult{operation, Result(err)}
	if c, ok := r.recorded[k]; ok {
		c.Inc()
	}
	if h, ok := r.duration[k]; ok {
		h.Observe(elapsed.Seconds())
	}
}

// RetentionMetrics counts what retention policies archive and purge. A nil
// *RetentionMetrics records nothing.
type RetentionMetrics struct {
	archived gometrics.Counter
	purged   gometrics.Counter
}

// NewRetentionMetrics registers the retention counters on m. A nil m returns
// nil.
func NewRetentionMetrics(m gometrics.Metrics) *RetentionMetrics {
	if m == nil {
		return nil
	}
	return &RetentionMetrics{
		archived: m.Counter(MetricEventsArchived,
			gometrics.WithDescription("Audit events retention copied to the archive sink before purging them.")),
		purged: m.Counter(MetricEventsPurged,
			gometrics.WithDescription("Audit events retention deleted from the store.")),
	}
}

// Add records one policy's archived and purged counts.
func (r *RetentionMetrics) Add(archived, purged int64) {
	if r == nil {
		return
	}
	if archived > 0 {
		r.archived.Add(float64(archived))
	}
	if purged > 0 {
		r.purged.Add(float64(purged))
	}
}

// CheckpointMetrics counts checkpoint attempts by result. A nil
// *CheckpointMetrics records nothing.
type CheckpointMetrics struct {
	attempted map[string]gometrics.Counter
}

// NewCheckpointMetrics registers the checkpoint counter on m. A nil m returns
// nil.
func NewCheckpointMetrics(m gometrics.Metrics) *CheckpointMetrics {
	if m == nil {
		return nil
	}
	c := &CheckpointMetrics{attempted: make(map[string]gometrics.Counter, 4)}
	for _, res := range []string{ResultOK, ResultNothingNew, ResultLostRace, ResultError} {
		c.attempted[res] = m.Counter(MetricCheckpointsAttempted,
			gometrics.WithDescription("Signed checkpoints Chronicle tried to take, by result."),
			gometrics.WithLabels(map[string]string{LabelResult: res}),
		)
	}
	return c
}

// Inc counts one attempt that ended in result.
func (c *CheckpointMetrics) Inc(result string) {
	if c == nil {
		return
	}
	if counter, ok := c.attempted[result]; ok {
		counter.Inc()
	}
}

type jobResult struct{ job, result string }

// SchedulerMetrics times the extension's background runs. A nil
// *SchedulerMetrics records nothing.
type SchedulerMetrics struct {
	duration map[jobResult]gometrics.Histogram
}

// NewSchedulerMetrics registers the run duration histogram on m. A nil m
// returns nil.
func NewSchedulerMetrics(m gometrics.Metrics) *SchedulerMetrics {
	if m == nil {
		return nil
	}
	s := &SchedulerMetrics{duration: make(map[jobResult]gometrics.Histogram, 4)}
	for _, job := range []string{JobRetention, JobCheckpoint} {
		for _, res := range []string{ResultOK, ResultError} {
			s.duration[jobResult{job, res}] = m.Histogram(MetricSchedulerRunDuration,
				gometrics.WithDescription("Time one scheduled retention or checkpoint run took."),
				gometrics.WithUnit("s"),
				gometrics.WithBuckets(SchedulerBuckets...),
				gometrics.WithLabels(map[string]string{LabelJob: job, LabelResult: res}),
			)
		}
	}
	return s
}

// Observe records one run of job that took elapsed and ended in err.
func (s *SchedulerMetrics) Observe(job string, err error, elapsed time.Duration) {
	if s == nil {
		return
	}
	if h, ok := s.duration[jobResult{job, Result(err)}]; ok {
		h.Observe(elapsed.Seconds())
	}
}
