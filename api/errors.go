package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// respondInternalError logs the real error server-side and returns a generic message to clients.
// Prevents leaking database table names, column names, and constraint details (Security P1#15).
func respondInternalError(c *gin.Context, err error, context string) {
	log.Printf("[ERROR] %s: %v", context, err)
	c.JSON(http.StatusInternalServerError, gin.H{
		"error": "an internal error occurred",
	})
}
