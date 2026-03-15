package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func listSkillsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	rows, err := dbPool.Query(c.Request.Context(),
		"SELECT id, skill_name, skill_slug, threat_types, mitre_tactics, mitre_techniques, severity_default, investigation_methodology, detection_patterns, example_prompt, times_used, version, is_community, (code_template IS NOT NULL) as has_template FROM agent_skills WHERE is_active = true AND (tenant_id = $1 OR tenant_id IS NULL) ORDER BY times_used DESC",
		tenantID,
	)
	if err != nil {
		respondInternalError(c, err, "query skills")
		return
	}
	defer rows.Close()

	var skills []map[string]interface{}
	for rows.Next() {
		var id, skillName, skillSlug, severityDefault, invMethodology, detPatterns, exPrompt string
		var threatTypes, mitreTactics, mitreTechniques []string
		var timesUsed, version int
		var isCommunity, hasTemplate bool

		if err := rows.Scan(&id, &skillName, &skillSlug, &threatTypes, &mitreTactics, &mitreTechniques, &severityDefault, &invMethodology, &detPatterns, &exPrompt, &timesUsed, &version, &isCommunity, &hasTemplate); err != nil {
			log.Printf("Error scanning skill row: %v", err)
			continue
		}

		skill := map[string]interface{}{
			"id":                        id,
			"skill_name":                skillName,
			"skill_slug":                skillSlug,
			"threat_types":              threatTypes,
			"mitre_tactics":             mitreTactics,
			"mitre_techniques":          mitreTechniques,
			"severity_default":          severityDefault,
			"investigation_methodology": invMethodology,
			"detection_patterns":        detPatterns,
			"example_prompt":            exPrompt,
			"times_used":                timesUsed,
			"version":                   version,
			"is_community":              isCommunity,
			"has_template":              hasTemplate,
		}
		skills = append(skills, skill)
	}

	if skills == nil {
		skills = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"skills": skills, "count": len(skills)})
}
