package main

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestRBAC_AdminCanAccessTenants verifies that requireRole("admin") does not
// produce a 403 for an admin-role token.  Without a database the handler will
// return 500, but not 403.
func TestRBAC_AdminCanAccessTenants(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "admin@zovark.local", "admin")
	w := makeRequest(router, "GET", "/api/v1/tenants", nil, token)
	if w.Code == http.StatusForbidden {
		t.Errorf("Admin should not get 403 on GET /api/v1/tenants, got %d", w.Code)
	}
}

// TestRBAC_AnalystCannotCreateTenant verifies that the "analyst" role is
// rejected with 403 on the admin-only POST /tenants endpoint.
func TestRBAC_AnalystCannotCreateTenant(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "analyst@zovark.local", "analyst")
	w := makeRequest(router, "POST", "/api/v1/tenants",
		map[string]string{"name": "test", "slug": "test"}, token)
	if w.Code != http.StatusForbidden {
		t.Errorf("Analyst should get 403 on POST /api/v1/tenants, got %d", w.Code)
	}
}

// TestRBAC_ViewerCannotCreateTenant verifies that the "viewer" role is
// rejected with 403 on the admin-only POST /tenants endpoint.
func TestRBAC_ViewerCannotCreateTenant(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "viewer@zovark.local", "viewer")
	w := makeRequest(router, "POST", "/api/v1/tenants",
		map[string]string{"name": "test", "slug": "test"}, token)
	if w.Code != http.StatusForbidden {
		t.Errorf("Viewer should get 403 on POST /api/v1/tenants, got %d", w.Code)
	}
}

// TestRBAC_AnalystCannotListTenants verifies that the "analyst" role is
// rejected with 403 on the admin-only GET /tenants endpoint.
func TestRBAC_AnalystCannotListTenants(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "analyst@zovark.local", "analyst")
	w := makeRequest(router, "GET", "/api/v1/tenants", nil, token)
	if w.Code != http.StatusForbidden {
		t.Errorf("Analyst should get 403 on GET /api/v1/tenants, got %d", w.Code)
	}
}

// TestRBAC_AnalystCannotDeleteTenantData verifies that the "analyst" role
// cannot trigger a GDPR erasure (admin-only endpoint).
func TestRBAC_AnalystCannotDeleteTenantData(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "analyst@zovark.local", "analyst")
	w := makeRequest(router, "DELETE", "/api/v1/tenants/tenant-1/data", nil, token)
	if w.Code != http.StatusForbidden {
		t.Errorf("Analyst should get 403 on DELETE /api/v1/tenants/:id/data, got %d", w.Code)
	}
}

// TestRBAC_ViewerCannotDeleteTenantData verifies that the "viewer" role
// is also rejected on the GDPR endpoint.
func TestRBAC_ViewerCannotDeleteTenantData(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "viewer@zovark.local", "viewer")
	w := makeRequest(router, "DELETE", "/api/v1/tenants/tenant-1/data", nil, token)
	if w.Code != http.StatusForbidden {
		t.Errorf("Viewer should get 403 on DELETE /api/v1/tenants/:id/data, got %d", w.Code)
	}
}

// TestRBAC_AdminCanAccessModels verifies that requireRole("admin") does not
// produce a 403 for an admin-role token on GET /models.
func TestRBAC_AdminCanAccessModels(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "admin@zovark.local", "admin")
	w := makeRequest(router, "GET", "/api/v1/models", nil, token)
	if w.Code == http.StatusForbidden {
		t.Errorf("Admin should not get 403 on GET /api/v1/models, got %d", w.Code)
	}
}

// TestRBAC_AnalystCannotAccessModels verifies that the "analyst" role is
// rejected on the admin-only GET /models endpoint.
func TestRBAC_AnalystCannotAccessModels(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "analyst@zovark.local", "analyst")
	w := makeRequest(router, "GET", "/api/v1/models", nil, token)
	if w.Code != http.StatusForbidden {
		t.Errorf("Analyst should get 403 on GET /api/v1/models, got %d", w.Code)
	}
}

// TestRBAC_ViewerCannotAccessModels verifies that the "viewer" role is
// rejected on the admin-only GET /models endpoint.
func TestRBAC_ViewerCannotAccessModels(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "viewer@zovark.local", "viewer")
	w := makeRequest(router, "GET", "/api/v1/models", nil, token)
	if w.Code != http.StatusForbidden {
		t.Errorf("Viewer should get 403 on GET /api/v1/models, got %d", w.Code)
	}
}

// TestRBAC_AnyAuthenticatedCanAccessSkills verifies that the /skills endpoint
// (no requireRole guard) is reachable by admin, analyst, and viewer roles.
func TestRBAC_AnyAuthenticatedCanAccessSkills(t *testing.T) {
	router := setupTestRouter()
	roles := []string{"admin", "analyst", "viewer"}
	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			token := createTestJWT("tenant-1", "user-1", role+"@zovark.local", role)
			w := makeRequest(router, "GET", "/api/v1/skills", nil, token)
			if w.Code == http.StatusForbidden {
				t.Errorf("Role %q should not get 403 on GET /api/v1/skills, got %d", role, w.Code)
			}
			if w.Code == http.StatusUnauthorized {
				t.Errorf("Role %q should not get 401 on GET /api/v1/skills, got %d", role, w.Code)
			}
		})
	}
}

// TestRBAC_UnknownRoleCannotAccessAdminEndpoints verifies that an unrecognised
// role string does not accidentally gain admin access.
func TestRBAC_UnknownRoleCannotAccessAdminEndpoints(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "rogue@zovark.local", "rogue_role")
	w := makeRequest(router, "GET", "/api/v1/tenants", nil, token)
	if w.Code != http.StatusForbidden {
		t.Errorf("Unknown role should get 403 on admin endpoint, got %d", w.Code)
	}
}

// TestRBAC_RequireRole_MissingContextKey verifies that if user_role is somehow
// absent from the context, requireRole returns 403.
func TestRBAC_RequireRole_MissingContextKey(t *testing.T) {
	// Build a router that has requireRole but no authMiddleware setting the key.
	router := setupBareRoleRouter()
	w := makeRequest(router, "GET", "/test-role", nil, "")
	if w.Code != http.StatusForbidden {
		t.Errorf("Missing user_role context key should produce 403, got %d", w.Code)
	}
}

// setupBareRoleRouter returns a minimal router that exercises requireRole
// without authMiddleware so we can test the "no user_role key" branch.
func setupBareRoleRouter() *gin.Engine {
	r := gin.New()
	r.GET("/test-role", requireRole("admin"), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})
	return r
}
