package user

import (
	"context"
	"errors"
	"fmt"
	"time"

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

	encrypted, err := s.cm.Encrypt(secret)
	if err != nil {
		return fmt.Errorf("加密 MFA 密钥失败: %w", err)
	}

	return s.repo.UpdateMfa(ctx, userID, "totp", encrypted)
}

func (s *userService) DisableMFA(ctx context.Context, userID int64) error {
	return s.repo.UpdateMfa(ctx, userID, "", "")
}
