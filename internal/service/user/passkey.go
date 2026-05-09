package user

import (
	"context"

	"github.com/go-webauthn/webauthn/webauthn"
)

func (s *userService) SetPasskeyState(ctx context.Context, token string, data webauthn.SessionData) error {
	return s.repo.SetPasskeyState(ctx, token, data)
}

func (s *userService) GetPasskeyState(ctx context.Context, token string) (webauthn.SessionData, error) {
	return s.repo.GetPasskeyState(ctx, token)
}
