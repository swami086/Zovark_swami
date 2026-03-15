package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type Playbook struct {
	ID                   string    `json:"id"`
	TenantID             *string   `json:"tenant_id,omitempty"`
	Name                 string    `json:"name"`
	Description          string    `json:"description,omitempty"`
	Icon                 string    `json:"icon"`
	TaskType             string    `json:"task_type"`
	IsTemplate           bool      `json:"is_template"`
	SystemPromptOverride *string   `json:"system_prompt_override,omitempty"`
	Steps                []string  `json:"steps"`
	CreatedBy            *string   `json:"created_by,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type CreatePlaybookRequest struct {
	Name                 string   `json:"name" binding:"required"`
	Description          string   `json:"description"`
	Icon                 string   `json:"icon"`
	TaskType             string   `json:"task_type" binding:"required"`
	SystemPromptOverride *string  `json:"system_prompt_override"`
	Steps                []string `json:"steps" binding:"required,min=1,max=3"`
}

func listPlaybooksHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(),
		"SELECT id, tenant_id, name, description, icon, task_type, is_template, system_prompt_override, steps, created_by, created_at, updated_at FROM playbooks WHERE tenant_id = $1 OR is_template = true ORDER BY is_template DESC, created_at DESC",
		tenantID,
	)
	if err != nil {
		respondInternalError(c, err, "list playbooks")
		return
	}
	defer rows.Close()

	var playbooks []Playbook
	for rows.Next() {
		var p Playbook
		var stepsJSON []byte
		err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.Icon, &p.TaskType, &p.IsTemplate, &p.SystemPromptOverride, &stepsJSON, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
		if err != nil {
			respondInternalError(c, err, "scan playbook row")
			return
		}
		json.Unmarshal(stepsJSON, &p.Steps)
		playbooks = append(playbooks, p)
	}

	if playbooks == nil {
		playbooks = []Playbook{}
	}

	c.JSON(http.StatusOK, playbooks)
}

func createPlaybookHandler(c *gin.Context) {
	var req CreatePlaybookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)

	if req.Icon == "" {
		req.Icon = "🔍"
	}

	stepsJSON, _ := json.Marshal(req.Steps)

	var p Playbook
	var returnedStepsJSON []byte
	err := dbPool.QueryRow(c.Request.Context(),
		`INSERT INTO playbooks (tenant_id, name, description, icon, task_type, is_template, system_prompt_override, steps, created_by) 
		 VALUES ($1, $2, $3, $4, $5, false, $6, $7, $8) 
		 RETURNING id, tenant_id, name, description, icon, task_type, is_template, system_prompt_override, steps, created_by, created_at, updated_at`,
		tenantID, req.Name, req.Description, req.Icon, req.TaskType, req.SystemPromptOverride, stepsJSON, userID,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.Icon, &p.TaskType, &p.IsTemplate, &p.SystemPromptOverride, &returnedStepsJSON, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)

	if err != nil {
		respondInternalError(c, err, "create playbook")
		return
	}
	json.Unmarshal(returnedStepsJSON, &p.Steps)

	c.JSON(http.StatusCreated, p)
}

func updatePlaybookHandler(c *gin.Context) {
	id := c.Param("id")
	var req CreatePlaybookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := c.MustGet("tenant_id").(string)
	stepsJSON, _ := json.Marshal(req.Steps)

	if req.Icon == "" {
		req.Icon = "🔍"
	}

	result, err := dbPool.Exec(c.Request.Context(),
		`UPDATE playbooks SET name = $1, description = $2, icon = $3, task_type = $4, system_prompt_override = $5, steps = $6, updated_at = NOW() 
		 WHERE id = $7 AND tenant_id = $8 AND is_template = false`,
		req.Name, req.Description, req.Icon, req.TaskType, req.SystemPromptOverride, stepsJSON, id, tenantID,
	)

	if err != nil {
		respondInternalError(c, err, "update playbook")
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "playbook not found or cannot be edited"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "playbook updated"})
}

func deletePlaybookHandler(c *gin.Context) {
	id := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	result, err := dbPool.Exec(c.Request.Context(),
		"DELETE FROM playbooks WHERE id = $1 AND tenant_id = $2 AND is_template = false",
		id, tenantID,
	)

	if err != nil {
		respondInternalError(c, err, "delete playbook")
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "playbook not found or cannot be deleted"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "playbook deleted"})
}
