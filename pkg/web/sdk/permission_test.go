package sdk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gin-gonic/gin"
)

func TestResolvePolicyPathWithPrefix(t *testing.T) {
	s := NewSDKWithURL("http://127.0.0.1:9000").WithPathPrefix("/api/plugin-runtime/builtin.ssh")

	if got := s.resolvePolicyPath("/sftp/delete"); got != "/api/plugin-runtime/builtin.ssh/sftp/delete" {
		t.Fatalf("unexpected resolved path: %s", got)
	}
	if got := s.resolvePolicyPath("/"); got != "/api/plugin-runtime/builtin.ssh" {
		t.Fatalf("unexpected root path: %s", got)
	}
}

func TestCheckPolicyInjectsVerifiedDecision(t *testing.T) {
	gin.SetMode(gin.TestMode)

	decision := pbac.Decision{
		Allowed:       true,
		FilterProfile: "rows",
		AllowAccessScope: &pbac.AccessScope{Predicate: &pbac.Predicate{
			Key:      "row:owner",
			Operator: pbac.StringEquals,
			Values:   []pbac.Operand{pbac.Literal("alice")},
		}},
	}
	authorizationServer := newAuthorizationServer(t, decision)
	defer authorizationServer.Close()

	var received pbac.Decision
	registry := capability.NewRegistry("sdk-test", "row", "SDK test")
	handler := registry.Capability("List rows", "list").
		AccessScope("rows").
		Handle(func(ctx *gin.Context) {
			received, _ = pbac.DecisionFromContext(ctx.Request.Context())
			ctx.Status(http.StatusNoContent)
		})

	engine := gin.New()
	engine.Use(NewSDKWithURL(authorizationServer.URL).CheckPolicy())
	engine.GET("/rows", handler)

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rows", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("expected request to continue, got status %d", response.Code)
	}
	if !received.Allowed || received.FilterProfile != "rows" || received.AllowAccessScope == nil {
		t.Fatalf("decision was not injected into the request context: %#v", received)
	}
}

func TestCheckPolicyRejectsProfileMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authorizationServer := newAuthorizationServer(t, pbac.Decision{
		Allowed:       true,
		FilterProfile: "other_rows",
	})
	defer authorizationServer.Close()

	called := false
	registry := capability.NewRegistry("sdk-mismatch-test", "row", "SDK mismatch test")
	handler := registry.Capability("List rows", "list").
		AccessScope("rows").
		Handle(func(ctx *gin.Context) {
			called = true
			ctx.Status(http.StatusNoContent)
		})

	engine := gin.New()
	engine.Use(NewSDKWithURL(authorizationServer.URL).CheckPolicy())
	engine.GET("/rows", handler)

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rows", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected profile mismatch to be rejected, got status %d", response.Code)
	}
	if called {
		t.Fatal("business handler must not run after a profile mismatch")
	}
}

func newAuthorizationServer(t *testing.T, decision pbac.Decision) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/permission/check_policy" {
			t.Errorf("unexpected authorization path: %s", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(apiResult[pbac.Decision]{Data: decision}); err != nil {
			t.Errorf("encode authorization response: %v", err)
		}
	}))
}
