package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ============================================================
// STANDARD API RESPONSE ENVELOPE (Issue #9)
// ============================================================

// APIResponse is the standard response envelope for all API endpoints.
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
	Meta    *APIMeta    `json:"meta,omitempty"`
}

// APIError represents a structured error in the response envelope.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// APIMeta contains pagination metadata.
type APIMeta struct {
	Page    int `json:"page,omitempty"`
	PerPage int `json:"per_page,omitempty"`
	Total   int `json:"total,omitempty"`
}

// respondOK sends a 200 response with data wrapped in the standard envelope.
func respondOK(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
	})
}

// respondCreated sends a 201 response with data wrapped in the standard envelope.
func respondCreated(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Data:    data,
	})
}

// respondError sends an error response wrapped in the standard envelope.
func respondError(c *gin.Context, status int, code, message string) {
	c.JSON(status, APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
		},
	})
}

// respondList sends a paginated list response wrapped in the standard envelope.
func respondList(c *gin.Context, data interface{}, page, perPage, total int) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
		Meta: &APIMeta{
			Page:    page,
			PerPage: perPage,
			Total:   total,
		},
	})
}
