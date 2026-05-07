package passkey

import (
	"context"
	"encoding/base64"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type IPasskeyService interface {
	// BeginRegistration 开始 Passkey 注册仪式，返回 CredentialCreation 给前端
	BeginRegistration(ctx context.Context, user domain.User) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	// FinishRegistration 完成注册仪式，将浏览器返回的公钥存入 Identity Hub
	FinishRegistration(ctx context.Context, user domain.User, sessionData webauthn.SessionData, response *protocol.ParsedCredentialCreationData) error
	// BeginLogin 开始 Passkey 登录仪式（Discoverable / 无用户名模式）
	BeginLogin(ctx context.Context, identitySource domain.IdentitySource) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	// FinishLogin 完成登录仪式，校验签名并返回领域用户
	FinishLogin(ctx context.Context, sessionData webauthn.SessionData, response *protocol.ParsedCredentialAssertionData) (domain.User, error)
}

type passkeyService struct {
	repo repository.IUserRepository
}

func NewPasskeyService(repo repository.IUserRepository) IPasskeyService {
	return &passkeyService{repo: repo}
}

// getWebAuthnConfig 根据身份源配置构造 WebAuthn 实例
func (s *passkeyService) getWebAuthnConfig(config domain.PasskeyConfig) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:                  config.RPID,
		RPDisplayName:         config.RPName,
		RPOrigins:             config.RPOrigins,
		AttestationPreference: protocol.ConveyancePreference(config.AttestationPreference),
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// NOTE: Passkey 必须要求 ResidentKey，这样凭证才会存储在设备上
			UserVerification: protocol.UserVerificationRequirement(config.UserVerification),
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
		},
	})
}

// BeginRegistration 生成注册挑战码，发送给前端浏览器
func (s *passkeyService) BeginRegistration(ctx context.Context, user domain.User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	// TODO: 从数据库获取 Passkey 身份源配置，当前暂时硬编码
	cfg := domain.PasskeyConfig{
		RPID:      "localhost",
		RPName:    "EIAM",
		RPOrigins: []string{"http://localhost:5173"},
	}

	w, err := s.getWebAuthnConfig(cfg)
	if err != nil {
		return nil, nil, err
	}

	waUser := NewWebauthnUser(user, user.Identities)
	return w.BeginRegistration(waUser)
}

// FinishRegistration 校验浏览器的注册响应，将公钥写入 Identity Hub
func (s *passkeyService) FinishRegistration(ctx context.Context, user domain.User, sessionData webauthn.SessionData, response *protocol.ParsedCredentialCreationData) error {
	cfg := domain.PasskeyConfig{
		RPID:      "localhost",
		RPName:    "EIAM",
		RPOrigins: []string{"http://localhost:3333"},
	}

	w, err := s.getWebAuthnConfig(cfg)
	if err != nil {
		return err
	}

	waUser := NewWebauthnUser(user, user.Identities)
	credential, err := w.CreateCredential(waUser, sessionData, response)
	if err != nil {
		return err
	}

	// 存入 Identity Hub（统一的 UserIdentity 表）
	newIdentity := domain.UserIdentity{
		UserID:     user.ID,
		Provider:   "passkey",
		IdentityID: base64.StdEncoding.EncodeToString(credential.ID),
		PasskeyInfo: domain.PasskeyInfo{
			PublicKey:       credential.PublicKey,
			AttestationType: credential.AttestationType,
			AAGUID:          credential.Authenticator.AAGUID,
			SignCount:       credential.Authenticator.SignCount,
		},
	}

	return s.repo.BatchUpsert(ctx, []domain.User{{
		ID:         user.ID,
		Identities: []domain.UserIdentity{newIdentity},
	}})
}

// BeginLogin 生成登录挑战码（Discoverable 模式，不需要知道用户名）
func (s *passkeyService) BeginLogin(ctx context.Context, identitySource domain.IdentitySource) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	w, err := s.getWebAuthnConfig(identitySource.PasskeyConfig)
	if err != nil {
		return nil, nil, err
	}

	return w.BeginDiscoverableLogin()
}

// FinishLogin 校验浏览器的登录签名，根据 CredentialID 反查用户
func (s *passkeyService) FinishLogin(ctx context.Context, sessionData webauthn.SessionData, response *protocol.ParsedCredentialAssertionData) (domain.User, error) {
	// 1. 获取 Passkey 配置
	cfg := domain.PasskeyConfig{
		RPID:      "localhost",
		RPName:    "EIAM",
		RPOrigins: []string{"http://localhost:3333"},
	}
	w, err := s.getWebAuthnConfig(cfg)
	if err != nil {
		return domain.User{}, err
	}

	// 2. 定义 User 查找 Handler（Discoverable Login 核心回调）
	// NOTE: 浏览器会带回 rawID 和 userHandle，我们用 rawID 在 Identity Hub 中反查用户
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		credentialID := base64.StdEncoding.EncodeToString(rawID)
		u, findErr := s.repo.FindByIdentity(ctx, "passkey", credentialID)
		if findErr != nil {
			return nil, findErr
		}
		return NewWebauthnUser(u, u.Identities), nil
	}

	// 3. 执行校验
	waUser, credential, err := w.ValidatePasskeyLogin(handler, sessionData, response)
	if err != nil {
		return domain.User{}, err
	}

	// 4. 转换回领域模型并更新签名计数（防重放攻击）
	user := waUser.(*WebauthnUser).user
	user.Identities = waUser.(*WebauthnUser).credentials

	credentialID := base64.StdEncoding.EncodeToString(credential.ID)
	for i := range user.Identities {
		if user.Identities[i].Provider == "passkey" && user.Identities[i].IdentityID == credentialID {
			user.Identities[i].PasskeyInfo.SignCount = credential.Authenticator.SignCount
			break
		}
	}
	_ = s.repo.BatchUpsert(ctx, []domain.User{user})

	return user, nil
}
