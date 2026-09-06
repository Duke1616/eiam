package sessionx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

type stubProvider struct {
	destroyFn func(ctx *gctx.Context) error
	getFn     func(ctx *gctx.Context) (session.Session, error)
}

func (s *stubProvider) NewSession(ctx *gctx.Context, uid int64, jwtData map[string]string, sessData map[string]any) (session.Session, error) {
	return nil, nil
}

func (s *stubProvider) Get(ctx *gctx.Context) (session.Session, error) {
	if s.getFn != nil {
		return s.getFn(ctx)
	}
	return nil, nil
}

func (s *stubProvider) Destroy(ctx *gctx.Context) error {
	if s.destroyFn != nil {
		return s.destroyFn(ctx)
	}
	return nil
}

func (s *stubProvider) UpdateClaims(ctx *gctx.Context, claims session.Claims) error {
	return nil
}

func (s *stubProvider) RenewAccessToken(ctx *gctx.Context) error {
	return nil
}

func TestDestroy_NilContext(t *testing.T) {
	assert.NoError(t, Destroy(nil))
	assert.NoError(t, DestroyGin(nil))
}

func TestDestroy_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	called := false
	provider := &stubProvider{
		destroyFn: func(ctx *gctx.Context) error {
			called = true
			return nil
		},
	}
	session.SetDefaultProvider(provider)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/logout", nil)
	gctx := &ginx.Context{Context: c}

	err := Destroy(gctx)
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestDestroyGin_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	called := false
	provider := &stubProvider{
		destroyFn: func(ctx *gctx.Context) error {
			called = true
			return nil
		},
	}
	session.SetDefaultProvider(provider)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/logout", nil)

	err := DestroyGin(c)
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestDestroy_Fallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	expectedErr := errors.New("provider destroy error")
	provider := &stubProvider{
		destroyFn: func(ctx *gctx.Context) error {
			return expectedErr
		},
		getFn: func(ctx *gctx.Context) (session.Session, error) {
			return nil, errors.New("get session error")
		},
	}
	session.SetDefaultProvider(provider)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/logout", nil)
	gctx := &ginx.Context{Context: c}

	err := Destroy(gctx)
	assert.Equal(t, expectedErr, err)
}
