package core

import "fmt"

// Plan §3.2 / A3: compare instants, not the original JSON strings. Keep the
// fraction outside database date conversion: SQLite dates have millisecond
// precision and PostgreSQL timestamps have microsecond precision.
// https://www.sqlite.org/lang_datefunc.html
// https://www.postgresql.org/docs/16/datatype-datetime.html
// RFC 3339 §5.6 supplies the fixed date/time prefix and numeric offset grammar.
func sqliteSessionInstant(value string) string {
	base, fraction := sessionInstantParts(value)
	return "strftime('%Y-%m-%dT%H:%M:%S'," + base + ") || '.' || " + fraction + " || 'Z'"
}

func postgresSessionInstant(value string) string {
	base, fraction := sessionInstantParts(value)
	return "to_char((" + base + ")::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || '.' || " + fraction + " || 'Z'"
}

func sessionInstantParts(value string) (string, string) {
	zone := "(CASE WHEN substr(" + value + ",length(" + value + "),1)='Z' THEN 'Z' ELSE substr(" + value + ",length(" + value + ")-5,6) END)"
	fraction := "(CASE WHEN substr(" + value + ",20,1)='.' THEN substr(" + value + ",21,length(" + value + ")-20-length(" + zone + ")) ELSE '' END)"
	return "substr(" + value + ",1,19) || " + zone, "substr(" + fraction + " || '000000000',1,9)"
}

func (e *Engine) sessionSummariesSQL(where string, limit, offset int) string {
	instant := sqliteSessionInstant("stamp")
	agents := "json_group_array(agent)"
	devices := "json_group_array(json_object('nodeId',node,'name',name))"
	if e.postgres {
		instant = postgresSessionInstant("stamp")
		agents = "CAST(json_agg(agent) AS TEXT)"
		devices = "CAST(json_agg(json_build_object('nodeId',node,'name',name)) AS TEXT)"
	}
	// LD2: union the two sources before grouping so orphan reviews and zero-call
	// instances survive. Every records access is explicitly tenant-scoped, in
	// addition to the existing PostgreSQL transaction-local RLS context.
	return fmt.Sprintf(`WITH source AS (
 SELECT %s AS session_id, COALESCE(NULLIF(%s,''),'pi') AS agent,
   '' AS node, %s AS stamp, 1 AS is_review
 FROM records r WHERE r.tenant_id=$1 AND r.kind='reviews'
 UNION ALL
 SELECT %s, COALESCE(NULLIF(%s,''),'pi'), COALESCE(%s,''), %s, 0
 FROM records r WHERE r.tenant_id=$1 AND r.kind='instances'
 ), activity AS (
 SELECT session_id,agent,node,%s AS instant,is_review FROM source
 ), summaries AS (
 SELECT session_id,MIN(instant) AS session_time,
 MAX(CASE WHEN is_review=1 THEN instant END) AS last_call_at,
 SUM(is_review) AS call_count FROM activity GROUP BY session_id
 ), filtered AS (SELECT s.* FROM summaries s %s),
 paged AS (SELECT * FROM filtered ORDER BY session_time DESC,session_id DESC LIMIT $%d OFFSET $%d)
 SELECT totals.total,p.session_id,p.session_time,p.last_call_at,p.call_count,
 (SELECT %s FROM (SELECT DISTINCT a.agent FROM activity a WHERE a.session_id=p.session_id ORDER BY a.agent) agents),
 (SELECT %s FROM (
   SELECT DISTINCT a.node,COALESCE(%s,'') AS name FROM activity a
   LEFT JOIN records n ON n.tenant_id=$1 AND n.kind='client_nodes' AND n.id=a.node
   WHERE a.session_id=p.session_id AND a.node<>'' ORDER BY a.node
 ) devices)
 FROM (SELECT COUNT(*) AS total FROM filtered) totals LEFT JOIN paged p ON 1=1
 ORDER BY p.session_time DESC,p.session_id DESC`,
		e.jsonField("r.", "sessionId"), e.jsonField("r.", "agent"), e.jsonField("r.", "createdAt"),
		e.jsonField("r.", "sessionId"), e.jsonField("r.", "agent"), e.jsonField("r.", "nodeId"), e.jsonField("r.", "startedAt"),
		instant, where, limit, offset, agents, devices, e.jsonField("n.", "name"))
}
