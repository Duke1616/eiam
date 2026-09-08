package domain

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/samber/lo"
)

// CasXMLNamespace CAS 协议标准 XML 命名空间
const CasXMLNamespace = "http://www.yale.edu/tp/cas"

// CasTicketData 存储在 Redis 中的 CAS 票据元数据
type CasTicketData struct {
	Ticket    string    `json:"ticket"`
	UserID    int64     `json:"user_id"`
	TenantID  int64     `json:"tenant_id"`
	Username  string    `json:"username"`
	Service   string    `json:"service"`
	CreatedAt time.Time `json:"created_at"`
}

// IsExpired 判定票据在指定生存期 (TTL) 下是否已超时
func (t *CasTicketData) IsExpired(ttl time.Duration) bool {
	return time.Since(t.CreatedAt) > ttl
}

// MatchesService 校验待验票的目标 Service 与当初签发时的 Service 是否一致
func (t *CasTicketData) MatchesService(reqService string) bool {
	return MatchCasService(t.Service, reqService)
}

// MatchCasService 比对两个 CAS Service URL 是否一致
// 遵循 CAS 规范：忽略 ticket 参数、忽略大小写与末尾斜杠、安全比对 scheme/host/path/query
func MatchCasService(origin, target string) bool {
	if origin == target {
		return true
	}

	u1, err1 := url.Parse(origin)
	u2, err2 := url.Parse(target)
	if err1 != nil || err2 != nil {
		return origin == target
	}

	// 比较 scheme, host, path (忽略路径末尾斜杠差异)
	if !strings.EqualFold(u1.Scheme, u2.Scheme) ||
		!strings.EqualFold(u1.Host, u2.Host) ||
		strings.TrimRight(u1.Path, "/") != strings.TrimRight(u2.Path, "/") {
		return false
	}

	// 移除 ticket 参数后比较 query (客户端重定向后常携带 ticket 参数)
	q1 := u1.Query()
	q1.Del("ticket")
	q2 := u2.Query()
	q2.Del("ticket")

	return q1.Encode() == q2.Encode()
}

// CasValidationResult CAS 票据校验成功后的用户信息结果
type CasValidationResult struct {
	User       User
	Attributes map[string]any
}

// ToServiceResponse 将校验结果转换为 CAS 2.0 / 3.0 标准 XML 根响应对象
func (r *CasValidationResult) ToServiceResponse() CasServiceResponse {
	return NewCasSuccessResponse(r.User.Username, r.Attributes)
}

// ToJsonResponse 将校验结果转换为 CAS 3.0 标准 JSON 根响应对象
func (r *CasValidationResult) ToJsonResponse() CasJsonResponse {
	return NewCasSuccessJsonResponse(r.User.Username, r.Attributes)
}

// CasServiceResponse CAS 2.0 / 3.0 统一 XML 根响应
type CasServiceResponse struct {
	XMLName               xml.Name                  `xml:"cas:serviceResponse"`
	XmlnsCas              string                    `xml:"xmlns:cas,attr"`
	AuthenticationSuccess *CasAuthenticationSuccess `xml:"cas:authenticationSuccess,omitempty"`
	AuthenticationFailure *CasAuthenticationFailure `xml:"cas:authenticationFailure,omitempty"`
}

// ToXML 将 CAS XML 响应领域实体序列化为格式化 XML 文本
func (r CasServiceResponse) ToXML() (string, error) {
	output, err := xml.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// NewCasSuccessResponse 构造 CAS 认证成功的 XML 领域实体
func NewCasSuccessResponse(username string, attributes map[string]any) CasServiceResponse {
	resp := CasServiceResponse{
		XmlnsCas: CasXMLNamespace,
		AuthenticationSuccess: &CasAuthenticationSuccess{
			User: username,
		},
	}

	if len(attributes) > 0 {
		keys := lo.Keys(attributes)
		slices.Sort(keys)

		var customAttrs []CasCustomAttribute
		for _, k := range keys {
			valStr := fmt.Sprintf("%v", attributes[k])
			if valStr != "" {
				customAttrs = append(customAttrs, CasCustomAttribute{
					XMLName: xml.Name{Local: "cas:" + k},
					Value:   valStr,
				})
			}
		}
		resp.AuthenticationSuccess.Attributes = &CasAttributesList{
			Attributes: customAttrs,
		}
	}
	return resp
}

// NewCasFailureResponse 构造 CAS 认证失败的 XML 领域实体
func NewCasFailureResponse(code, message string) CasServiceResponse {
	if code == "" {
		code = "INVALID_TICKET"
	}
	return CasServiceResponse{
		XmlnsCas: CasXMLNamespace,
		AuthenticationFailure: &CasAuthenticationFailure{
			Code:    code,
			Message: message,
		},
	}
}

// CasAuthenticationSuccess CAS 校验成功节点
type CasAuthenticationSuccess struct {
	User       string             `xml:"cas:user"`
	Attributes *CasAttributesList `xml:"cas:attributes,omitempty"`
}

// CasAuthenticationFailure CAS 校验失败节点
type CasAuthenticationFailure struct {
	Code    string `xml:"code,attr"`
	Message string `xml:",chardata"`
}

// CasAttributesList 承载用户扩展属性列表
type CasAttributesList struct {
	Attributes []CasCustomAttribute `xml:",any"`
}

// CasCustomAttribute 自定义属性键值对
type CasCustomAttribute struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// CasJsonResponse CAS 3.0 标准 JSON 协议根响应对象
type CasJsonResponse struct {
	ServiceResponse CasJsonServiceResponse `json:"serviceResponse"`
}

// NewCasSuccessJsonResponse 构造 CAS 认证成功的 JSON 响应领域实体
func NewCasSuccessJsonResponse(username string, attributes map[string]any) CasJsonResponse {
	return CasJsonResponse{
		ServiceResponse: CasJsonServiceResponse{
			AuthenticationSuccess: &CasJsonSuccess{
				User:       username,
				Attributes: attributes,
			},
		},
	}
}

// NewCasFailureJsonResponse 构造 CAS 认证失败的 JSON 响应领域实体
func NewCasFailureJsonResponse(code, message string) CasJsonResponse {
	if code == "" {
		code = "INVALID_TICKET"
	}
	return CasJsonResponse{
		ServiceResponse: CasJsonServiceResponse{
			AuthenticationFailure: &CasJsonFailure{
				Code:        code,
				Description: message,
			},
		},
	}
}

// CasJsonServiceResponse 包含认证成功或失败结果
type CasJsonServiceResponse struct {
	AuthenticationSuccess *CasJsonSuccess `json:"authenticationSuccess,omitempty"`
	AuthenticationFailure *CasJsonFailure `json:"authenticationFailure,omitempty"`
}

// CasJsonSuccess 认证成功 JSON 节点
type CasJsonSuccess struct {
	User       string         `json:"user"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// CasJsonFailure 认证失败 JSON 节点
type CasJsonFailure struct {
	Code        string `json:"code"`
	Description string `json:"description"`
}
