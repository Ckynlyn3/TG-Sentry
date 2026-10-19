package core

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type RiskVerdictCounts struct {
	Block int64 `json:"block"`
	Alert int64 `json:"alert"`
	Other int64 `json:"other"`
}
type RiskStatsTotals struct {
	RiskVerdictCounts
	Total           int64 `json:"total"`
	SeverityUnknown int64 `json:"severity_unknown"`
	Unattributed    int64 `json:"unattributed"`
	FutureExcluded  int64 `json:"future_excluded"`
}
type RiskStatsBucket struct {
	RiskVerdictCounts
	Start   int64 `json:"start"`
	End     int64 `json:"end"`
	Partial bool  `json:"partial"`
}
type RiskStatsCategory struct {
	RiskVerdictCounts
	Category string `json:"category"`
}
type RiskStatsAgent struct {
	RiskVerdictCounts
	Agent    string `json:"agent"`
	LastSeen int64  `json:"last_seen"`
}
type RiskStats struct {
	Window        string              `json:"window"`
	From          int64               `json:"from"`
	To            int64               `json:"to"`
	GeneratedAt   int64               `json:"generated_at"`
	BucketMS      int64               `json:"bucket_ms"`
	Totals        RiskStatsTotals     `json:"totals"`
	Buckets       []RiskStatsBucket   `json:"buckets"`
	ByCategory    []RiskStatsCategory `json:"by_category"`
	Uncategorized int64               `json:"uncategorized"`
	TopAgents     []RiskStatsAgent    `json:"top_agents"`
}

// PostgreSQL 16 §9.16/§7.2.1.4: array position, not the CloudEvents ID,
// distinguishes identical occurrences. SQLite json_each.key is its counterpart.
// https://www.postgresql.org/docs/16/functions-json.html
// https://www.sqlite.org/json1.html#the_json_each_and_json_tree_table_valued_functions
const riskStatsPostgres = `WITH expanded AS (
 SELECT r.id AS row_id, ev.ordinality AS position,
 COALESCE((ev.value->'data'->>'time')::bigint,0) AS occurred,
 COALESCE((ev.value->'data'->>'severity_id')::integer,0) AS severity,
 COALESCE(ev.value->'data'->'actor'->>'app_uid','') COLLATE "C" AS agent,
 COALESCE((ev.value->'data'->>'action_id')::integer,0) AS action,
 COALESCE((ev.value->'data'->>'disposition_id')::integer,0) AS disposition,
 COALESCE(ev.value->'data'->'finding_info'->>'types','[]') AS categories,
 COALESCE(json_array_length(ev.value->'data'->'finding_info'->'types'),0) AS category_count
 FROM records r CROSS JOIN LATERAL json_array_elements(r.payload::json->'events') WITH ORDINALITY ev(value,ordinality)
 WHERE r.tenant_id=$1 AND r.kind='audit' AND ev.value->>'type'='tg.sentry.risk.v1'
), filtered AS (
 SELECT * FROM expanded WHERE ($2::integer=-1 OR severity=$2) AND ($4::text='' OR agent=$4)
 AND ($3::text='' OR EXISTS (SELECT FROM json_array_elements_text(categories::json) c WHERE c.value=$3))
)`
const riskStatsPostgresLabels = `, labels AS (
 SELECT DISTINCT s.row_id,s.position,c.value COLLATE "C" AS category,s.block,s.alert,s.other
 FROM selected s CROSS JOIN LATERAL json_array_elements_text(s.categories::json) c
)`

const riskStatsSQLite = `WITH expanded AS (
 SELECT r.id AS row_id, ev.key AS position,
 COALESCE(json_extract(ev.value,'$.data.time'),0) AS occurred,
 COALESCE(json_extract(ev.value,'$.data.severity_id'),0) AS severity,
 COALESCE(json_extract(ev.value,'$.data.actor.app_uid'),'') AS agent,
 COALESCE(json_extract(ev.value,'$.data.action_id'),0) AS action,
 COALESCE(json_extract(ev.value,'$.data.disposition_id'),0) AS disposition,
 COALESCE(json_extract(ev.value,'$.data.finding_info.types'),'[]') AS categories,
 COALESCE(json_array_length(ev.value,'$.data.finding_info.types'),0) AS category_count
 FROM records r CROSS JOIN json_each(r.payload,'$.events') ev
 WHERE r.tenant_id=$1 AND r.kind='audit' AND json_extract(ev.value,'$.type')='tg.sentry.risk.v1'
), filtered AS (
 SELECT * FROM expanded WHERE ($2=-1 OR severity=$2) AND ($4='' OR agent=$4)
 AND ($3='' OR EXISTS (SELECT 1 FROM json_each(categories) c WHERE c.value=$3))
)`
const riskStatsSQLiteLabels = `, labels AS (
 SELECT DISTINCT s.row_id,s.position,c.value AS category,s.block,s.alert,s.other
 FROM selected s CROSS JOIN json_each(s.categories) c
)`

// A2: metadata precedes time selection; category expansion never multiplies
// occurrence totals. One UNION ALL statement keeps every section on one snapshot.
// Top 5 and ascending tie breaks are the binding plan's named local exceptions.
const riskStatsAggregates = `, metadata AS (
 SELECT COALESCE(MIN(CASE WHEN occurred<$5 THEN occurred END),$5) AS earliest,
 COALESCE(SUM(CASE WHEN occurred>=$5 THEN 1 ELSE 0 END),0) AS future FROM filtered
), bounds AS (
 SELECT CASE WHEN $7=1 THEN earliest ELSE $6 END AS lower_bound FROM metadata
), selected AS (
 SELECT f.*, CASE WHEN action=2 AND disposition=2 THEN 1 ELSE 0 END AS block,
 CASE WHEN action=3 AND disposition=19 THEN 1 ELSE 0 END AS alert,
 CASE WHEN (action=2 AND disposition=2) OR (action=3 AND disposition=19) THEN 0 ELSE 1 END AS other
 FROM filtered f CROSS JOIN bounds b WHERE occurred>=b.lower_bound AND occurred<$5
){{labels}}, categories_ranked AS (
 SELECT category,COUNT(*) AS total,SUM(block) AS block,SUM(alert) AS alert,SUM(other) AS other
 FROM labels GROUP BY category ORDER BY total DESC,category ASC LIMIT 5
), agents_ranked AS (
 SELECT agent,COUNT(*) AS total,SUM(block) AS block,SUM(alert) AS alert,SUM(other) AS other,MAX(occurred) AS last_seen
 FROM selected WHERE agent<>'' GROUP BY agent ORDER BY total DESC,agent ASC LIMIT 5
)
 SELECT 'metadata' AS section,'' AS label,earliest AS at,0 AS total,0 AS block,0 AS alert,0 AS other,0 AS unknown,0 AS unattributed,0 AS uncategorized,future FROM metadata
 UNION ALL
 SELECT 'totals','',0,COUNT(*),COALESCE(SUM(block),0),COALESCE(SUM(alert),0),COALESCE(SUM(other),0),
 COALESCE(SUM(CASE WHEN severity=0 THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN agent='' THEN 1 ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN category_count=0 THEN 1 ELSE 0 END),0),0 FROM selected
 UNION ALL
 SELECT 'bucket','',occurred-((occurred % $8+$8) % $8),COUNT(*),SUM(block),SUM(alert),SUM(other),0,0,0,0
 FROM selected GROUP BY occurred-((occurred % $8+$8) % $8)
 UNION ALL
 SELECT 'category',category,0,total,block,alert,other,0,0,0,0 FROM categories_ranked
 UNION ALL
 SELECT 'agent',agent,last_seen,total,block,alert,other,0,0,0,0 FROM agents_ranked
 ORDER BY section,total DESC,label ASC`

// RiskStats owns the request's read-only tenant transaction; it never loads
// riskEvents(). Postgres repeatable read follows §13.2.2; SQLite uses its native
// read transaction (https://www.sqlite.org/isolation.html), not an unsupported
// SQL isolation level. All errors return the zero DTO, never partial totals.
func (e *Engine) RiskStats(ctx context.Context, filter RiskEventFilter, window string) (RiskStats, error) {
	if !validRiskFilter(filter) || !hasExact(window, "24h", "7d", "all") {
		return RiskStats{}, ErrRiskEventQuery
	}
	now := e.clock().UTC().UnixMilli()
	result := RiskStats{Window: window, To: now, GeneratedAt: now, BucketMS: int64(24 * time.Hour / time.Millisecond), Buckets: []RiskStatsBucket{}, ByCategory: []RiskStatsCategory{}, TopAgents: []RiskStatsAgent{}}
	switch window {
	case "24h":
		result.From = now - int64(24*time.Hour/time.Millisecond)
		result.BucketMS = int64(time.Hour / time.Millisecond)
	case "7d":
		result.From = now - int64(7*24*time.Hour/time.Millisecond)
	}
	opts := &sql.TxOptions{ReadOnly: true}
	if e.postgres {
		opts.Isolation = sql.LevelRepeatableRead
	}
	tx, err := e.beginTenantTx(ctx, opts)
	if err != nil {
		return RiskStats{}, fmt.Errorf("begin risk stats: %w", err)
	}
	defer tx.Rollback()
	counts, earliest, err := e.readRiskStats(ctx, tx, &result, filter)
	if err != nil {
		return RiskStats{}, err
	}
	if err = tx.Commit(); err != nil {
		return RiskStats{}, fmt.Errorf("commit risk stats: %w", err)
	}
	if earliest < now {
		err = fillRiskStatsBuckets(ctx, &result, counts)
	} else {
		err = ctx.Err()
	}
	if err != nil {
		return RiskStats{}, err
	}
	return result, nil
}

func (e *Engine) readRiskStats(ctx context.Context, tx *sql.Tx, result *RiskStats, filter RiskEventFilter) (map[int64]RiskVerdictCounts, int64, error) {
	prefix, labels := riskStatsSQLite, riskStatsSQLiteLabels
	if e.postgres {
		prefix, labels = riskStatsPostgres, riskStatsPostgresLabels
	}
	severity := -1
	if filter.Severity != "" {
		severity = severityID(filter.Severity)
	}
	all := 0
	if result.Window == "all" {
		all = 1
	}
	rows, err := tx.QueryContext(ctx, prefix+strings.Replace(riskStatsAggregates, "{{labels}}", labels, 1), eventTenant(), severity, filter.Category, filter.Agent, result.To, result.From, all, result.BucketMS)
	if err != nil {
		return nil, 0, fmt.Errorf("query risk stats: %w", err)
	}
	defer rows.Close()
	counts := map[int64]RiskVerdictCounts{}
	earliest := result.To
	for rows.Next() {
		if err = scanRiskStats(rows, result, counts, &earliest); err != nil {
			return nil, 0, fmt.Errorf("scan risk stats: %w", err)
		}
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("read risk stats: %w", err)
	}
	if err = rows.Close(); err != nil {
		return nil, 0, fmt.Errorf("close risk stats: %w", err)
	}
	return counts, earliest, nil
}

func scanRiskStats(rows *sql.Rows, result *RiskStats, counts map[int64]RiskVerdictCounts, earliest *int64) error {
	var section, label string
	var at, total, unknown, unattributed, uncategorized, future int64
	var verdict RiskVerdictCounts
	if err := rows.Scan(&section, &label, &at, &total, &verdict.Block, &verdict.Alert, &verdict.Other, &unknown, &unattributed, &uncategorized, &future); err != nil {
		return err
	}
	switch section {
	case "metadata":
		*earliest = at
		result.Totals.FutureExcluded = future
		if result.Window == "all" {
			result.From = at
		}
	case "totals":
		result.Totals.RiskVerdictCounts = verdict
		result.Totals.Total = total
		result.Totals.SeverityUnknown = unknown
		result.Totals.Unattributed = unattributed
		result.Uncategorized = uncategorized
	case "bucket":
		counts[at] = verdict
	case "category":
		result.ByCategory = append(result.ByCategory, RiskStatsCategory{RiskVerdictCounts: verdict, Category: label})
	case "agent":
		result.TopAgents = append(result.TopAgents, RiskStatsAgent{RiskVerdictCounts: verdict, Agent: label, LastSeen: at})
	default:
		return fmt.Errorf("unknown risk stats section %s", strconv.Quote(section))
	}
	return nil
}

func fillRiskStatsBuckets(ctx context.Context, result *RiskStats, counts map[int64]RiskVerdictCounts) error {
	width := result.BucketMS
	nominal := time.UnixMilli(result.From).UTC().Truncate(time.Duration(width) * time.Millisecond).UnixMilli()
	for nominal < result.To {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("fill risk stats buckets: %w", err)
		}
		end := nominal + width
		result.Buckets = append(result.Buckets, RiskStatsBucket{RiskVerdictCounts: counts[nominal], Start: max(nominal, result.From), End: min(end, result.To), Partial: nominal < result.To && result.To < end})
		nominal = end
	}
	return ctx.Err()
}
