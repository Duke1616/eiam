package certx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertx_GenerateSelfSigned_And_BundleMethods(t *testing.T) {
	testCases := []struct {
		name          string
		cfg           CertConfig
		checkSubject  string
		checkOrg      string
		expectedYears int
		expectedDur   time.Duration
	}{
		{
			name:          "默认配置",
			cfg:           CertConfig{},
			checkSubject:  "EIAM SAML Identity Provider",
			checkOrg:      "EIAM Enterprise",
			expectedYears: 3,
		},
		{
			name: "按年自定义配置",
			cfg: CertConfig{
				CommonName:    "Custom SAML IdP",
				Organization:  "Custom Org",
				ValidityYears: 5,
				KeyBits:       2048,
			},
			checkSubject:  "Custom SAML IdP",
			checkOrg:      "Custom Org",
			expectedYears: 5,
		},
		{
			name: "精准 Duration 有效期 (短效2小时)",
			cfg: CertConfig{
				CommonName:   "Short Lived Cert",
				Organization: "Short Org",
				Validity:     2 * time.Hour,
				KeyBits:      2048,
			},
			checkSubject: "Short Lived Cert",
			checkOrg:     "Short Org",
			expectedDur:  2 * time.Hour,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bundle, err := GenerateSelfSigned(tc.cfg)
			require.NoError(t, err)
			require.NotNil(t, bundle)
			require.NotNil(t, bundle.X509)
			require.NotNil(t, bundle.Key)

			// 校验主体身份
			assert.Equal(t, tc.checkSubject, bundle.CommonName())
			require.NotEmpty(t, bundle.X509.Subject.Organization)
			assert.Equal(t, tc.checkOrg, bundle.X509.Subject.Organization[0])

			// 校验有效期精准性
			if tc.expectedDur > 0 {
				assert.Equal(t, bundle.X509.NotBefore.Add(tc.expectedDur), bundle.X509.NotAfter)
			} else {
				assert.Equal(t, bundle.X509.NotBefore.Year()+tc.expectedYears, bundle.X509.NotAfter.Year())
				assert.Equal(t, bundle.X509.NotBefore.Month(), bundle.X509.NotAfter.Month())
				assert.Equal(t, bundle.X509.NotBefore.Day(), bundle.X509.NotAfter.Day())
			}

			// 校验内聚导出的 PEM、Base64DER 与指纹
			assert.Contains(t, bundle.CertPEM(), "-----BEGIN CERTIFICATE-----")
			assert.Contains(t, bundle.KeyPEM(), "-----BEGIN RSA PRIVATE KEY-----")
			assert.Contains(t, bundle.CombinedPEM(), "-----BEGIN CERTIFICATE-----")
			assert.Contains(t, bundle.CombinedPEM(), "-----BEGIN RSA PRIVATE KEY-----")
			assert.NotEmpty(t, bundle.Base64DER())
			assert.Contains(t, bundle.Fingerprint(), ":")

			// 校验由导出的 PEM 重新组装 New
			reconstructed, err := New(bundle.CertPEM(), bundle.KeyPEM())
			require.NoError(t, err)
			assert.Equal(t, bundle.X509.SerialNumber, reconstructed.X509.SerialNumber)
			assert.Equal(t, bundle.Key.N, reconstructed.Key.N)
		})
	}
}

func TestCertx_KeyOperations(t *testing.T) {
	// 1. RSA 私钥生成与 PKCS1 解析
	privKey, err := GenerateRSAKey(2048)
	require.NoError(t, err)

	keyPEM := EncodeKeyPEM(privKey)
	assert.Contains(t, keyPEM, "-----BEGIN RSA PRIVATE KEY-----")

	parsedKey, err := ParseKey(keyPEM)
	require.NoError(t, err)
	assert.Equal(t, privKey.N, parsedKey.N)

	// 2. PKCS8 编码私钥解析
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(t, err)
	pkcs8PEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}))
	parsedPKCS8, err := ParseKey(pkcs8PEM)
	require.NoError(t, err)
	assert.Equal(t, privKey.N, parsedPKCS8.N)

	// 3. 公钥导出与解析
	pubPEM, err := EncodePublicKeyPEM(&privKey.PublicKey)
	require.NoError(t, err)
	assert.Contains(t, pubPEM, "-----BEGIN PUBLIC KEY-----")

	parsedPub, err := ParsePublicKey(pubPEM)
	require.NoError(t, err)
	assert.Equal(t, privKey.PublicKey.N, parsedPub.N)
}

func TestCertx_GenericTypeMismatch(t *testing.T) {
	// 生成 ECDSA 密钥以 PKCS8 导出
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: ecBytes,
	}))

	// 期望解析为 *rsa.PrivateKey 时应安全返回类型不匹配错误
	_, err = ParseKeyAs[*rsa.PrivateKey](ecPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "私钥类型不匹配")

	// 正确按 *ecdsa.PrivateKey 解析应成功
	parsedEC, err := ParseKeyAs[*ecdsa.PrivateKey](ecPEM)
	require.NoError(t, err)
	assert.Equal(t, ecKey.X, parsedEC.X)
}

func TestCertx_ResolveSource(t *testing.T) {
	t.Run("本地文件读取", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "test.crt")

		bundle, err := GenerateSelfSigned(CertConfig{CommonName: "File Test"})
		require.NoError(t, err)

		err = os.WriteFile(certPath, []byte(bundle.CertPEM()), 0600)
		require.NoError(t, err)

		parsed, err := ParseCert(certPath)
		require.NoError(t, err)
		assert.Equal(t, "File Test", parsed.Subject.CommonName)
	})

	t.Run("不存在的文件路径明确报错", func(t *testing.T) {
		_, err := ResolveSource("/path/to/non/existent/cert.crt")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "读取证书/密钥文件失败")
	})

	t.Run("内联 PEM 字符串优先识别", func(t *testing.T) {
		inlinePEM := "-----BEGIN CERTIFICATE-----\nMIICFAKE...\n-----END CERTIFICATE-----"
		bytes, err := ResolveSource(inlinePEM)
		require.NoError(t, err)
		assert.Equal(t, []byte(inlinePEM), bytes)
	})

	t.Run("多行非文件数据源防误判", func(t *testing.T) {
		multiline := "somedata\notherdata"
		bytes, err := ResolveSource(multiline)
		require.NoError(t, err)
		assert.Equal(t, []byte(multiline), bytes)
	})

	t.Run("空数据源报错", func(t *testing.T) {
		_, err := ResolveSource("")
		require.Error(t, err)
	})
}
