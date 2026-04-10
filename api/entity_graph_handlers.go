package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

// listEntityGraphHandler returns up to 500 entities (most recent first) and edges touching that set.
// GET /api/v1/entities?type=&limit=
func listEntityGraphHandler(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.MustGet("tenant_id").(string)

	limit := 500
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 500 {
			limit = n
		}
	}
	etype := c.Query("type")

	var rows pgx.Rows
	var err error
	if etype != "" {
		rows, err = dbPool.Query(ctx, `
			WITH top_entities AS (
				SELECT id FROM entities
				WHERE tenant_id = $1 AND entity_type = $2
				ORDER BY last_seen DESC NULLS LAST
				LIMIT $3
			)
			SELECT e.id::text, e.entity_type, e.value, e.first_seen, e.last_seen,
			       e.observation_count, e.threat_score, COALESCE(e.metadata, '{}'::jsonb)
			FROM entities e
			INNER JOIN top_entities t ON e.id = t.id
			ORDER BY e.last_seen DESC NULLS LAST
		`, tenantID, etype, limit)
	} else {
		rows, err = dbPool.Query(ctx, `
			WITH top_entities AS (
				SELECT id FROM entities
				WHERE tenant_id = $1
				ORDER BY last_seen DESC NULLS LAST
				LIMIT $2
			)
			SELECT e.id::text, e.entity_type, e.value, e.first_seen, e.last_seen,
			       e.observation_count, e.threat_score, COALESCE(e.metadata, '{}'::jsonb)
			FROM entities e
			INNER JOIN top_entities t ON e.id = t.id
			ORDER BY e.last_seen DESC NULLS LAST
		`, tenantID, limit)
	}
	if err != nil {
		respondInternalError(c, err, "query entities graph")
		return
	}
	defer rows.Close()

	entities, err := scanEntityRows(rows)
	if err != nil {
		respondInternalError(c, err, "scan entities graph")
		return
	}

	var erows pgx.Rows
	if etype != "" {
		erows, err = dbPool.Query(ctx, `
			WITH top_entities AS (
				SELECT id FROM entities
				WHERE tenant_id = $1 AND entity_type = $2
				ORDER BY last_seen DESC NULLS LAST
				LIMIT $3
			)
			SELECT ee.id::text, ee.source_entity_id::text, ee.target_entity_id::text,
			       ee.edge_type, ee.confidence::float8, ee.observed_at
			FROM entity_edges ee
			WHERE ee.tenant_id = $1
			  AND (ee.source_entity_id IN (SELECT id FROM top_entities)
			    OR ee.target_entity_id IN (SELECT id FROM top_entities))
			LIMIT 5000
		`, tenantID, etype, limit)
	} else {
		erows, err = dbPool.Query(ctx, `
			WITH top_entities AS (
				SELECT id FROM entities
				WHERE tenant_id = $1
				ORDER BY last_seen DESC NULLS LAST
				LIMIT $2
			)
			SELECT ee.id::text, ee.source_entity_id::text, ee.target_entity_id::text,
			       ee.edge_type, ee.confidence::float8, ee.observed_at
			FROM entity_edges ee
			WHERE ee.tenant_id = $1
			  AND (ee.source_entity_id IN (SELECT id FROM top_entities)
			    OR ee.target_entity_id IN (SELECT id FROM top_entities))
			LIMIT 5000
		`, tenantID, limit)
	}
	if err != nil {
		respondInternalError(c, err, "query entity edges")
		return
	}
	defer erows.Close()

	edges, err := scanEdgeRows(erows)
	if err != nil {
		respondInternalError(c, err, "scan entity edges")
		return
	}

	c.JSON(http.StatusOK, gin.H{"entities": entities, "edges": edges})
}

// entityNeighborhoodHandler returns the focal entity, its 1-hop neighbors, and incident edges.
// GET /api/v1/entities/:id/neighborhood
func entityNeighborhoodHandler(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.MustGet("tenant_id").(string)
	eid := c.Param("id")

	var exists bool
	err := dbPool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM entities WHERE id = $1::uuid AND tenant_id = $2)`,
		eid, tenantID,
	).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "entity not found"})
		return
	}

	rows, err := dbPool.Query(ctx, `
		WITH n AS (
			SELECT e.id FROM entities e
			WHERE e.tenant_id = $2
			  AND (e.id = $1::uuid
			    OR e.id IN (SELECT source_entity_id FROM entity_edges WHERE tenant_id = $2 AND target_entity_id = $1::uuid)
			    OR e.id IN (SELECT target_entity_id FROM entity_edges WHERE tenant_id = $2 AND source_entity_id = $1::uuid))
		)
		SELECT e.id::text, e.entity_type, e.value, e.first_seen, e.last_seen,
		       e.observation_count, e.threat_score, COALESCE(e.metadata, '{}'::jsonb)
		FROM entities e
		WHERE e.id IN (SELECT id FROM n)
		ORDER BY e.last_seen DESC NULLS LAST
		LIMIT 200
	`, eid, tenantID)
	if err != nil {
		respondInternalError(c, err, "neighborhood entities")
		return
	}
	defer rows.Close()

	entities, err := scanEntityRows(rows)
	if err != nil {
		respondInternalError(c, err, "scan neighborhood entities")
		return
	}

	erows, err := dbPool.Query(ctx, `
		WITH n AS (
			SELECT e.id FROM entities e
			WHERE e.tenant_id = $2
			  AND (e.id = $1::uuid
			    OR e.id IN (SELECT source_entity_id FROM entity_edges WHERE tenant_id = $2 AND target_entity_id = $1::uuid)
			    OR e.id IN (SELECT target_entity_id FROM entity_edges WHERE tenant_id = $2 AND source_entity_id = $1::uuid))
		)
		SELECT ee.id::text, ee.source_entity_id::text, ee.target_entity_id::text,
		       ee.edge_type, ee.confidence::float8, ee.observed_at
		FROM entity_edges ee
		WHERE ee.tenant_id = $2
		  AND (ee.source_entity_id IN (SELECT id FROM n) OR ee.target_entity_id IN (SELECT id FROM n))
		LIMIT 2000
	`, eid, tenantID)
	if err != nil {
		respondInternalError(c, err, "neighborhood edges")
		return
	}
	defer erows.Close()

	edges, err := scanEdgeRows(erows)
	if err != nil {
		respondInternalError(c, err, "scan neighborhood edges")
		return
	}

	c.JSON(http.StatusOK, gin.H{"entities": entities, "edges": edges})
}

func scanEntityRows(rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Err() error
}) ([]map[string]interface{}, error) {
	var entities []map[string]interface{}
	for rows.Next() {
		var id, et, val string
		var fs, ls interface{}
		var obs int
		var threat int
		var meta []byte
		if err := rows.Scan(&id, &et, &val, &fs, &ls, &obs, &threat, &meta); err != nil {
			return nil, err
		}
		if et == "file_hash" {
			et = "hash"
		}
		var md map[string]interface{}
		_ = json.Unmarshal(meta, &md)
		if md == nil {
			md = map[string]interface{}{}
		}
		entities = append(entities, map[string]interface{}{
			"id": id, "entity_type": et, "value": val,
			"first_seen": fs, "last_seen": ls,
			"investigation_count": obs, "risk_score": threat, "metadata": md,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if entities == nil {
		entities = []map[string]interface{}{}
	}
	return entities, nil
}

func scanEdgeRows(rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Err() error
}) ([]map[string]interface{}, error) {
	var edges []map[string]interface{}
	for rows.Next() {
		var id, src, tgt, rel string
		var conf float64
		var seen interface{}
		if err := rows.Scan(&id, &src, &tgt, &rel, &conf, &seen); err != nil {
			return nil, err
		}
		edges = append(edges, map[string]interface{}{
			"id": id, "source_id": src, "target_id": tgt, "relationship": rel,
			"confidence": conf, "first_seen": seen,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if edges == nil {
		edges = []map[string]interface{}{}
	}
	return edges, nil
}

