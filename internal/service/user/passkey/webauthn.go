package passkey

import (
	"encoding/base64"
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebauthnUser 适配器，将领域模型 User 转为 webauthn.User 接口实现
type WebauthnUser struct {
	user        domain.User
	credentials []domain.UserIdentity
}

func NewWebauthnUser(u domain.User, cs []domain.UserIdentity) *WebauthnUser {
	return &WebauthnUser{user: u, credentials: cs}
}

func (u *WebauthnUser) WebAuthnID() []byte {
	return []byte(fmt.Sprintf("%d", u.user.ID))
}

func (u *WebauthnUser) WebAuthnName() string {
	return u.user.Username
}

func (u *WebauthnUser) WebAuthnDisplayName() string {
	if u.user.Profile.Nickname != "" {
		return u.user.Profile.Nickname
	}
	return u.user.Username
}

func (u *WebauthnUser) WebAuthnIcon() string {
	return u.user.Profile.Avatar
}

func (u *WebauthnUser) WebAuthnCredentials() []webauthn.Credential {
	res := make([]webauthn.Credential, 0, len(u.credentials))
	for _, c := range u.credentials {
		if c.Provider != "passkey" {
			continue
		}
		rawID, _ := base64.StdEncoding.DecodeString(c.IdentityID)
		res = append(res, webauthn.Credential{
			ID:              rawID,
			PublicKey:       c.PasskeyInfo.PublicKey,
			AttestationType: c.PasskeyInfo.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.PasskeyInfo.AAGUID,
				SignCount: c.PasskeyInfo.SignCount,
			},
		})

	}
	return res
}
