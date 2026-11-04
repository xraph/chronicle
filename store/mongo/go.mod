module github.com/xraph/chronicle/store/mongo

go 1.26.0

toolchain go1.26.9

replace github.com/xraph/chronicle => ../..

require (
	github.com/xraph/chronicle v1.11.0
	github.com/xraph/grove v1.10.2
	github.com/xraph/grove/drivers/mongodriver v1.10.2
	go.mongodb.org/mongo-driver/v2 v2.9.2
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gofrs/uuid/v5 v5.3.2 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
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
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/term v0.46.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
