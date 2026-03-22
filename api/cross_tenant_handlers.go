package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GET /api/v1/intelligence/top-threats
// Returns top cross-tenant threat entities visible to the requesting tenant.
// Privacy-preserving: never returns other tenant IDs or investigation IDs.
func topThreatsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	// Return top 50 entities by threat score that the requesting tenant has observed,
	// enriched with cross-tenant intelligence (tenant_spread, techniques).
	rows, err := dbPool.Query(c.Request.Context(), `
		SELECT
			cte.entity_hash,
			cte.entity_type,
			cte.entity_value,
			cte.tenant_count,
			cte.threat_score,
			cte.first_seen,
			cte.last_seen,
			cte.metadata
		FROM cross_tenant_entities cte
		WHERE cte.entity_hash IN (
			SELECT DISTINCT e.entity_hash
			FROM entities e
			WHERE e.tenant_id = $1
		)
		ORDER BY cte.threat_score DESC
		LIMIT 50
	`, tenantID)
	if err != nil {
		respondInternalError(c, err, "query top threats")
		return
	}
	defer rows.Close()

	var threats []map[string]interface{}
	for rows.Next() {
		var entityHash, entityType, entityValue string
		var tenantCount int
		var threatScore float64
		var firstSeen, lastSeen interface{}
		var metadata []byte

		if err := rows.Scan(&entityHash, &entityType, &entityValue, &tenantCount,
			&threatScore, &firstSeen, &lastSeen, &metadata); err != nil {
			respondInternalError(c, err, "scan top threat row")
			return
		}

		threats = append(threats, map[string]interface{}{
			"entity_hash":  entityHash,
			"entity_type":  entityType,
			"entity_value": entityValue,
			"tenant_count": tenantCount,
			"threat_score": threatScore,
			"first_seen":   firstSeen,
			"last_seen":    lastSeen,
		})
	}

	if threats == nil {
		threats = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"threats": threats,
		"count":   len(threats),
	})
}

// GET /api/v1/intelligence/stats
// Returns cross-tenant correlation statistics.
func intelligenceStatsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	var totalEntities, crossTenantEntities int
	var avgThreatScore float64

	// Total entities for this tenant
	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM entities WHERE tenant_id = $1", tenantID,
	).Scan(&totalEntities)
	if err != nil {
		respondInternalError(c, err, "count entities")
		return
	}

	// Cross-tenant entities (entities this tenant has that are seen by 2+ tenants)
	err = dbPool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*), COALESCE(AVG(cte.threat_score), 0)
		FROM cross_tenant_entities cte
		WHERE cte.entity_hash IN (
			SELECT DISTINCT e.entity_hash FROM entities e WHERE e.tenant_id = $1
		)
	`, tenantID).Scan(&crossTenantEntities, &avgThreatScore)
	if err != nil {
		respondInternalError(c, err, "count cross-tenant entities")
		return
	}

	// Top entity types
	typeRows, err := dbPool.Query(c.Request.Context(), `
		SELECT cte.entity_type, COUNT(*) as cnt
		FROM cross_tenant_entities cte
		WHERE cte.entity_hash IN (
			SELECT DISTINCT e.entity_hash FROM entities e WHERE e.tenant_id = $1
		)
		GROUP BY cte.entity_type
		ORDER BY cnt DESC
		LIMIT 10
	`, tenantID)
	if err != nil {
		respondInternalError(c, err, "query entity type distribution")
		return
	}
	defer typeRows.Close()

	topEntityTypes := map[string]int{}
	for typeRows.Next() {
		var et string
		var cnt int
		typeRows.Scan(&et, &cnt)
		topEntityTypes[et] = cnt
	}

	// Technique distribution from entity observations linked to this tenant
	techRows, err := dbPool.Query(c.Request.Context(), `
		SELECT eo.mitre_technique, COUNT(DISTINCT eo.investigation_id) as cnt
		FROM entity_observations eo
		JOIN entities e ON e.id = eo.entity_id
		WHERE e.tenant_id = $1
		  AND eo.mitre_technique IS NOT NULL
		GROUP BY eo.mitre_technique
		ORDER BY cnt DESC
		LIMIT 10
	`, tenantID)
	if err != nil {
		respondInternalError(c, err, "query technique distribution")
		return
	}
	defer techRows.Close()

	techniqueDistribution := map[string]int{}
	for techRows.Next() {
		var tech string
		var cnt int
		techRows.Scan(&tech, &cnt)
		techniqueDistribution[tech] = cnt
	}

	c.JSON(http.StatusOK, gin.H{
		"total_entities":        totalEntities,
		"cross_tenant_entities": crossTenantEntities,
		"avg_threat_score":      avgThreatScore,
		"top_entity_types":      topEntityTypes,
		"technique_distribution": techniqueDistribution,
	})
}
