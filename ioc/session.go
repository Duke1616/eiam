// Copyright 2023 ecodeclub
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ioc

import (
	"strings"
	"time"

	"github.com/ecodeclub/ginx/session"
	"github.com/ecodeclub/ginx/session/cookie"
	"github.com/ecodeclub/ginx/session/header"
	"github.com/ecodeclub/ginx/session/mixin"
	ginRedis "github.com/ecodeclub/ginx/session/redis"
	"github.com/redis/go-redis/v9"
	"github.com/samber/lo"
	"github.com/spf13/viper"
)

type TokenCarrierSource string

const (
	TokenCarrierCookie TokenCarrierSource = "cookie"
	TokenCarrierToken  TokenCarrierSource = "token"
	TokenCarrierHeader                    = "X-Token-Carrier"
	sessionExpiration                     = 30 * 24 * time.Hour
)

func (t TokenCarrierSource) String() string {
	return string(t)
}

type sessionConfig struct {
	SessionEncryptedKey string              `mapstructure:"session_encrypted_key"`
	TokenCarrier        string              `mapstructure:"token_carrier"`
	Cookie              sessionCookieConfig `mapstructure:"cookie"`
}

type sessionCookieConfig struct {
	Domain string `mapstructure:"domain"`
	Name   string `mapstructure:"name"`
	Secure *bool  `mapstructure:"secure"`
}

func ConfiguredTokenCarrier() TokenCarrierSource {
	return parseTokenCarrier(viper.GetString("session.token_carrier"))
}

func parseTokenCarrier(value string) TokenCarrierSource {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", TokenCarrierCookie.String():
		return TokenCarrierCookie
	case TokenCarrierToken.String():
		return TokenCarrierToken
	default:
		panic("session.token_carrier must be cookie or token")
	}
}

func newCookieTokenCarrier(cfg sessionCookieConfig) *cookie.TokenCarrier {
	if cfg.Name == "" {
		panic("cookie.name is required")
	}
	if cfg.Domain == "" {
		panic("cookie.domain is required")
	}

	return &cookie.TokenCarrier{
		MaxAge:   int(sessionExpiration.Seconds()),
		Name:     cfg.Name,
		Path:     "/",
		Secure:   lo.FromPtrOr(cfg.Secure, true),
		HttpOnly: false,
		Domain:   cfg.Domain,
	}
}

func InitSession(cmd redis.Cmdable) session.Provider {
	var cfg sessionConfig
	if err := viper.UnmarshalKey("session", &cfg); err != nil {
		panic(err)
	}
	if cfg.SessionEncryptedKey == "" {
		panic("session_encrypted_key is required")
	}

	provider := ginRedis.NewSessionProvider(cmd, cfg.SessionEncryptedKey, sessionExpiration)
	headerCarrier := header.NewTokenCarrier()
	if parseTokenCarrier(cfg.TokenCarrier) == TokenCarrierToken {
		provider.TokenCarrier = headerCarrier
		return provider
	}
	provider.TokenCarrier = mixin.NewTokenCarrier(newCookieTokenCarrier(cfg.Cookie), headerCarrier)
	return provider
}
