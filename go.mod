module aegishook

go 1.26.0

// Keep npm-installed Go sources (e.g. flatted) out of ./... (go.mod ignore directive, Go 1.25+).
ignore ./console/node_modules

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/jackc/pgx/v5 v5.11.0
	github.com/pressly/goose/v3 v3.29.0
	golang.org/x/oauth2 v0.37.0
	golang.org/x/sys v0.49.0
	modernc.org/sqlite v1.60.1
	// Pin stack-overflow fix https://github.com/mvdan/sh/commit/0e0eb36bb6dd6a143842ffda25738e9a82dc915e; move to the first tagged release containing it.
	mvdan.cc/sh/v3 v3.14.1-0.20260928185915-0e0eb36bb6dd
)

require golang.org/x/text v0.43.0

require (
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/sethvargo/go-retry v0.5.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	modernc.org/libc v1.78.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
