package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// listMCPApprovalsHandler returns pending MCP workflow approvals.
// GET /api/v1/approvals/pending
func listMCPApprovalsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	approvals := getRedisPendingApprovals(tenantID)
	c.JSON(http.StatusOK, gin.H{"approvals": approvals, "count": len(approvals)})
}

// decideMCPApprovalHandler approves or denies an MCP workflow approval.
// POST /api/v1/approvals/:token/decide
func decideMCPApprovalHandler(c *gin.Context) {
	token := c.Param("token")
	userID := c.MustGet("user_id").(string)

	var req struct {
		Action string `json:"action" binding:"required"` // "approve" or "deny"
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Action != "approve" && req.Action != "deny" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be 'approve' or 'deny'"})
		return
	}

	// Read approval from Redis
	key := "hydra:approval:" + token
	data, err := redisCommand("GET", key)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "approval not found or expired"})
		return
	}

	approvalJSON := parseRedisBulkString(data)
	if approvalJSON == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "approval not found or expired"})
		return
	}

	var approval map[string]interface{}
	if err := json.Unmarshal([]byte(approvalJSON), &approval); err != nil {
		respondInternalError(c, err, "parse approval")
		return
	}

	if approval["status"] != "pending" {
		c.JSON(http.StatusConflict, gin.H{"error": "approval already decided"})
		return
	}

	// Update approval
	if req.Action == "approve" {
		approval["status"] = "approved"
		approval["approved_by"] = userID
		approval["approved_at"] = time.Now().Unix()
	} else {
		approval["status"] = "denied"
		approval["denied_by"] = userID
		approval["denied_at"] = time.Now().Unix()
		if req.Reason != "" {
			approval["deny_reason"] = req.Reason
		}
	}

	updatedJSON, _ := json.Marshal(approval)
	ttl := "60"
	if req.Action == "deny" {
		ttl = "300"
	}
	redisCommand("SETEX", key, ttl, string(updatedJSON))

	c.JSON(http.StatusOK, gin.H{
		"status":      approval["status"],
		"approval_id": approval["approval_id"],
		"decided_by":  userID,
	})
}

// parseRedisBulkString extracts the string from a Redis RESP bulk string.
func parseRedisBulkString(resp string) string {
	if len(resp) < 4 || resp[0] != '$' {
		return ""
	}
	// Skip $N\r\n prefix to get to data
	idx := 0
	for i := 1; i < len(resp); i++ {
		if resp[i] == '\r' && i+1 < len(resp) && resp[i+1] == '\n' {
			idx = i + 2
			break
		}
	}
	if idx == 0 || idx >= len(resp) {
		return ""
	}
	end := len(resp)
	if end >= 2 && resp[end-2] == '\r' && resp[end-1] == '\n' {
		end -= 2
	}
	return resp[idx:end]
}

func getRedisPendingApprovals(tenantID string) []map[string]interface{} {
	var approvals []map[string]interface{}
	// SCAN for approval keys and filter pending ones for this tenant
	// Simplified: uses KEYS pattern (acceptable for low-volume approval traffic)
	resp, err := redisCommand("KEYS", "hydra:approval:*")
	if err != nil {
		return approvals
	}

	// Parse RESP array — each key is a bulk string
	keys := parseRedisArray(resp)
	for _, key := range keys {
		if key == "" || len(key) > 100 {
			continue
		}
		// Skip index keys
		if len(key) > 17 && key[17:20] == "id:" {
			continue
		}
		data, err := redisCommand("GET", key)
		if err != nil {
			continue
		}
		jsonStr := parseRedisBulkString(data)
		if jsonStr == "" {
			continue
		}
		var approval map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &approval); err != nil {
			continue
		}
		if approval["status"] != "pending" {
			continue
		}
		if tid, ok := approval["tenant_id"].(string); ok && tid != tenantID {
			continue
		}
		// Don't expose raw Redis keys in response
		approvals = append(approvals, map[string]interface{}{
			"approval_id": approval["approval_id"],
			"workflow_id": approval["workflow_id"],
			"requested_by": approval["requested_by"],
			"status":       approval["status"],
			"created_at":   approval["created_at"],
			"expires_at":   approval["expires_at"],
		})
	}
	return approvals
}

func parseRedisArray(resp string) []string {
	// Parse RESP array: *N\r\n$len\r\nvalue\r\n...
	if len(resp) < 3 || resp[0] != '*' {
		return nil
	}
	var results []string
	i := 0
	// Skip *N\r\n
	for i < len(resp) && resp[i] != '\n' {
		i++
	}
	i++ // skip \n

	for i < len(resp) {
		if resp[i] == '$' {
			// Find length end
			j := i + 1
			for j < len(resp) && resp[j] != '\r' {
				j++
			}
			// Skip \r\n
			j += 2
			// Read value until \r\n
			k := j
			for k < len(resp) && resp[k] != '\r' {
				k++
			}
			if j <= k {
				results = append(results, resp[j:k])
			}
			i = k + 2 // skip \r\n
		} else {
			i++
		}
	}
	return results
}
