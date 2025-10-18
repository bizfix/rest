package rest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// TestAuthenticationConfigurations tests various authentication scenarios
func TestAuthenticationConfigurations(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *API
		validate func(t *testing.T, spec *openapi3.T)
	}{
		{
			name: "Custom Header Token Authentication",
			setup: func() *API {
				// Configure API with custom token auth header
				api := NewAPI("Auth Example",
					WithGlobalAuth(
						AuthScheme{
							Name:        "customTokenAuth",
							Type:        "apiKey",
							Description: "Custom token authentication using x_auth header",
							In:          "header",
							ParamName:   "x_auth",
						},
					),
				)

				api.Get("/users").
					HasResponseModel(http.StatusOK, ModelOf[AuthTestUser]())

				return api
			},
			validate: func(t *testing.T, spec *openapi3.T) {
				// Verify security scheme is defined
				if spec.Components.SecuritySchemes == nil {
					t.Fatal("SecuritySchemes not defined in components")
				}

				scheme, ok := spec.Components.SecuritySchemes["customTokenAuth"]
				if !ok {
					t.Fatal("customTokenAuth scheme not found")
				}

				if scheme.Value.Type != "apiKey" {
					t.Errorf("Expected type apiKey, got %s", scheme.Value.Type)
				}

				if scheme.Value.In != "header" {
					t.Errorf("Expected in=header, got %s", scheme.Value.In)
				}

				if scheme.Value.Name != "x_auth" {
					t.Errorf("Expected name=x_auth, got %s", scheme.Value.Name)
				}

				// Verify security is applied to operation
				getOp := spec.Paths.Value("/users").Get
				if getOp == nil {
					t.Fatal("GET /users operation not found")
				}

				if getOp.Security == nil || len(*getOp.Security) == 0 {
					t.Fatal("Security requirements not applied to operation")
				}

				found := false
				for _, req := range *getOp.Security {
					if _, ok := req["customTokenAuth"]; ok {
						found = true
						break
					}
				}

				if !found {
					t.Error("customTokenAuth not in security requirements")
				}
			},
		},
		{
			name: "Bearer Token Authentication",
			setup: func() *API {
				api := NewAPI("Bearer Auth Example",
					WithGlobalAuth(
						AuthScheme{
							Name:         "bearerAuth",
							Type:         "http",
							Description:  "Bearer token authentication",
							Scheme:       "bearer",
							BearerFormat: "JWT",
						},
					),
				)

				api.Get("/protected").
					HasResponseModel(http.StatusOK, ModelOf[AuthTestMessage]())

				return api
			},
			validate: func(t *testing.T, spec *openapi3.T) {
				scheme, ok := spec.Components.SecuritySchemes["bearerAuth"]
				if !ok {
					t.Fatal("bearerAuth scheme not found")
				}

				if scheme.Value.Type != "http" {
					t.Errorf("Expected type http, got %s", scheme.Value.Type)
				}

				if scheme.Value.Scheme != "bearer" {
					t.Errorf("Expected scheme bearer, got %s", scheme.Value.Scheme)
				}

				if scheme.Value.BearerFormat != "JWT" {
					t.Errorf("Expected bearerFormat JWT, got %s", scheme.Value.BearerFormat)
				}
			},
		},
		{
			name: "Mixed Global and Route-Specific Auth",
			setup: func() *API {
				api := NewAPI("Mixed Auth Example",
					WithGlobalAuth(
						AuthScheme{
							Name:        "apiKeyAuth",
							Type:        "apiKey",
							Description: "API Key authentication",
							In:          "header",
							ParamName:   "X-API-Key",
						},
					),
				)

				// Route with global auth
				api.Get("/public").
					HasResponseModel(http.StatusOK, ModelOf[AuthTestMessage]())

				// Route with custom auth
				api.Post("/admin").
					HasAuth("adminTokenAuth").
					HasRequestModel(ModelOf[AuthTestAdminRequest]()).
					HasResponseModel(http.StatusOK, ModelOf[AuthTestMessage]())

				return api
			},
			validate: func(t *testing.T, spec *openapi3.T) {
				// GET /public should have global apiKeyAuth
				getOp := spec.Paths.Value("/public").Get
				if getOp == nil {
					t.Fatal("GET /public operation not found")
				}

				if getOp.Security == nil || len(*getOp.Security) == 0 {
					t.Fatal("Security not applied to GET /public")
				}

				found := false
				for _, req := range *getOp.Security {
					if _, ok := req["apiKeyAuth"]; ok {
						found = true
						break
					}
				}

				if !found {
					t.Error("apiKeyAuth not in security requirements for GET /public")
				}

				// POST /admin should have custom adminTokenAuth
				postOp := spec.Paths.Value("/admin").Post
				if postOp == nil {
					t.Fatal("POST /admin operation not found")
				}

				if postOp.Security == nil || len(*postOp.Security) == 0 {
					t.Fatal("Security not applied to POST /admin")
				}

				adminFound := false
				for _, req := range *postOp.Security {
					if _, ok := req["adminTokenAuth"]; ok {
						adminFound = true
						break
					}
				}

				if !adminFound {
					t.Error("adminTokenAuth not in security requirements for POST /admin")
				}
			},
		},
		{
			name: "Multiple Authentication Schemes",
			setup: func() *API {
				api := NewAPI("Multiple Auth Example",
					WithGlobalAuth(
						AuthScheme{
							Name:        "apiKey",
							Type:        "apiKey",
							Description: "API Key authentication",
							In:          "header",
							ParamName:   "X-API-Key",
						},
						AuthScheme{
							Name:         "bearerToken",
							Type:         "http",
							Description:  "Bearer token authentication",
							Scheme:       "bearer",
							BearerFormat: "JWT",
						},
					),
				)

				api.Get("/resources").
					HasResponseModel(http.StatusOK, ModelOf[AuthTestResource]())

				return api
			},
			validate: func(t *testing.T, spec *openapi3.T) {
				// Both schemes should be defined
				if _, ok := spec.Components.SecuritySchemes["apiKey"]; !ok {
					t.Error("apiKey scheme not found")
				}

				if _, ok := spec.Components.SecuritySchemes["bearerToken"]; !ok {
					t.Error("bearerToken scheme not found")
				}

				// Both should be in security requirements
				getOp := spec.Paths.Value("/resources").Get
				if getOp.Security == nil {
					t.Fatal("Security not applied to operation")
				}

				apiKeyFound := false
				bearerFound := false
				for _, req := range *getOp.Security {
					if _, ok := req["apiKey"]; ok {
						apiKeyFound = true
					}
					if _, ok := req["bearerToken"]; ok {
						bearerFound = true
					}
				}

				if !apiKeyFound || !bearerFound {
					t.Error("Not all security schemes applied to operation")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := tt.setup()
			spec, err := api.Spec()
			if err != nil {
				t.Fatalf("Failed to generate spec: %v", err)
			}

			tt.validate(t, spec)

			// Pretty print the spec for visual inspection
			data, _ := json.MarshalIndent(spec, "", "  ")
			t.Logf("Generated OpenAPI spec:\n%s", string(data))
		})
	}
}

// Test models
type AuthTestUser struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type AuthTestMessage struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type AuthTestAdminRequest struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
}

type AuthTestResource struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Data  string `json:"data"`
}

// Example: Custom token header authentication
// Usage:
//   api := NewAPI("Example API",
//       WithGlobalAuth(
//           AuthScheme{
//               Name:        "customTokenAuth",
//               Type:        "apiKey",
//               Description: "Token-based authentication using custom header",
//               In:          "header",
//               ParamName:   "x_auth", // Custom header instead of Authorization
//           },
//       ),
//   )
//
//   api.Get("/api/v1/data").
//       HasDescription("Get data - requires x_auth header").
//       HasResponseModel(http.StatusOK, ModelOf[AuthTestMessage]()).
//       HasResponseModel(http.StatusUnauthorized, ModelOf[AuthTestMessage]())
//
//   spec, _ := api.Spec()
//   // Example request: GET /api/v1/data with header x_auth: your-token-here

// Example: Route-specific authentication
// Usage:
//   api := NewAPI("Multi-Auth API",
//       WithGlobalAuth(
//           AuthScheme{
//               Name:        "apiKey",
//               Type:        "apiKey",
//               Description: "API Key in header",
//               In:          "header",
//               ParamName:   "X-API-Key",
//           },
//       ),
//   )
//
//   api.Get("/public").
//       HasResponseModel(http.StatusOK, ModelOf[AuthTestMessage]())
//
//   api.Delete("/admin/users/{id}").
//       HasAuth("adminAuth").
//       HasPathParameter("id", PathParam{Description: "User ID"}).
//       HasResponseModel(http.StatusOK, ModelOf[AuthTestMessage]())
//
//   spec, _ := api.Spec()
