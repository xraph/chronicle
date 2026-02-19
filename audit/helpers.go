package audit

import "time"

// Convenience time range constructors.

// Today returns a TimeRange for today (midnight to now).
func Today() TimeRange {
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return TimeRange{After: start, Before: now}
}

// Yesterday returns a TimeRange for yesterday.
func Yesterday() TimeRange {
	now := time.Now().UTC()
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -1)
	return TimeRange{After: start, Before: end}
}

// ThisWeek returns a TimeRange from the start of this week (Monday) to now.
func ThisWeek() TimeRange {
	now := time.Now().UTC()
	weekday := int(now.Weekday())
	if weekday == 0 {
		weekday = 7 // Sunday
	}
	start := time.Date(now.Year(), now.Month(), now.Day()-(weekday-1), 0, 0, 0, 0, time.UTC)
	return TimeRange{After: start, Before: now}
}

// ThisMonth returns a TimeRange from the start of this month to now.
func ThisMonth() TimeRange {
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	return TimeRange{After: start, Before: now}
}

// LastMonth returns a TimeRange for the previous month.
func LastMonth() TimeRange {
	now := time.Now().UTC()
	end := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, -1, 0)
	return TimeRange{After: start, Before: end}
}

// LastYear returns a TimeRange for the previous year.
func LastYear() TimeRange {
	now := time.Now().UTC()
	end := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(-1, 0, 0)
	return TimeRange{After: start, Before: end}
}

// DateRange returns a TimeRange between two dates.
func DateRange(from, to time.Time) TimeRange {
	return TimeRange{After: from, Before: to}
}

// Last returns a TimeRange for the last duration from now.
func Last(d time.Duration) TimeRange {
	now := time.Now().UTC()
	return TimeRange{After: now.Add(-d), Before: now}
}
