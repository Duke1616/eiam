package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func (s *userService) GenerateTOTPSetup(ctx context.Context, userID int64) (string, string, error) {
	u, err := s.repo.FindById(ctx, userID)
	if err != nil {
		return "", "", err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "EIAM",
		AccountName: u.Username,
	})
	if err != nil {
		return "", "", err
	}

	return key.Secret(), key.URL(), nil
}

func (s *userService) VerifyAndEnableTOTP(ctx context.Context, userID int64, code, secret string) error {
	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1, // 允许上下 1 个周期（±30秒）的误差
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !valid {
		return errors.New("验证码不正确")
	}

	u, err := s.repo.FindById(ctx, userID)
	if err != nil {
		return err
	}

	u.MfaType = "totp"
	encrypted, err := s.cm.Encrypt(secret)
	if err != nil {
		return fmt.Errorf("加密 MFA 密钥失败: %w", err)
	}
	u.MfaSecret = encrypted

	_, err = s.repo.Update(ctx, u)
	return err
}

func (s *userService) DisableMFA(ctx context.Context, userID int64) error {
	u, err := s.repo.FindById(ctx, userID)
	if err != nil {
		return err
	}

	u.MfaType = ""
	u.MfaSecret = ""

	_, err = s.repo.Update(ctx, u)
	return err
}

func (s *userService) VerifyLoginMFA(ctx context.Context, token, code string) (domain.LoginResult, error) {
	// 1. 从缓存获取 UID
	uid, err := s.repo.GetMfaToken(ctx, token)
	if err != nil {
		return domain.LoginResult{}, ErrMfaTokenNotFound
	}

	// 2. 获取用户信息
	u, err := s.repo.FindById(ctx, uid)
	if err != nil {
		return domain.LoginResult{}, err
	}

	// 2.1 解密 MFA 密钥
	secret, err := s.cm.Decrypt(u.MfaSecret)
	if err != nil {
		return domain.LoginResult{}, fmt.Errorf("解密 MFA 密钥失败: %w", err)
	}

	// 3. 校验 TOTP
	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil || !valid {
		// 校验失败，增加失败次数记录
		attempts, _ := s.repo.IncMfaAttempts(ctx, token)
		if attempts >= 5 {
			_ = s.repo.DeleteMfaToken(ctx, token)
			return domain.LoginResult{}, ErrMfaAttemptsExhausted
		}
		return domain.LoginResult{}, fmt.Errorf("验证码错误 (剩余尝试次数: %d)", 5-attempts)
	}

	// 4. 校验成功，销毁令牌
	_ = s.repo.DeleteMfaToken(ctx, token)

	// 5. 执行后续登录逻辑
	return s.postLogin(ctx, u, false)
}
