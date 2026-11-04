module github.com/xraph/chronicle/internal/backendtest

go 1.26.0

toolchain go1.26.9

replace github.com/xraph/chronicle => ../..

require (
	github.com/xraph/chronicle v1.11.0
	github.com/xraph/chronicle/internal/pgtest v1.11.0
	github.com/xraph/chronicle/internal/redistest v1.11.0
	github.com/xraph/chronicle/store/mongo v1.11.0
	github.com/xraph/chronicle/store/postgres v1.11.0
	github.com/xraph/chronicle/store/redis v1.11.0
	github.com/xraph/chronicle/store/sqlite v1.11.0
	github.com/xraph/grove v1.10.2
	github.com/xraph/grove/drivers/mongodriver v1.10.2
	github.com/xraph/grove/drivers/pgdriver v1.10.2
	github.com/xraph/grove/drivers/sqlitedriver v1.10.2
	github.com/xraph/grove/kv v1.10.2
	github.com/xraph/grove/kv/drivers/redisdriver v1.10.2
	go.mongodb.org/mongo-driver/v2 v2.9.2
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gofrs/uuid/v5 v5.3.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.12.0 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/redis/go-redis/v9 v9.23.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.2.0 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/xraph/go-utils v1.5.0 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	go.jetify.com/typeid/v2 v2.0.0-alpha.3 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20260727155853-b88d891fe743 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/term v0.46.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af // indirect
	modernc.org/libc v1.68.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.46.1 // indirect
)

replace github.com/xraph/chronicle/store/postgres => ../../store/postgres

replace github.com/xraph/chronicle/store/sqlite => ../../store/sqlite

replace github.com/xraph/chronicle/store/mongo => ../../store/mongo

replace github.com/xraph/chronicle/store/redis => ../../store/redis

replace github.com/xraph/chronicle/internal/pgtest => ../../internal/pgtest

replace github.com/xraph/chronicle/internal/redistest => ../../internal/redistest
