package swagger

// Spec OpenAPI 3.0 顶级根规范对象
type Spec struct {
	OpenAPI    string               `json:"openapi"`
	Info       Info                 `json:"info"`
	Security   []SecurityRequirement `json:"security,omitempty"`
	Paths      map[string]PathItem  `json:"paths"`
	Tags       []Tag                `json:"tags,omitempty"`
	Components *Components          `json:"components,omitempty"`
}

type Info struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

type Tag struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type SecurityRequirement map[string][]string

type PathItem map[string]Operation

type Operation struct {
	Tags        []string            `json:"tags"`
	Summary     string              `json:"summary"`
	Description string              `json:"description,omitempty"`
	OperationID string              `json:"operationId,omitempty"`
	Parameters  []Parameter         `json:"parameters,omitempty"`
	RequestBody *RequestBody        `json:"requestBody,omitempty"`
	Responses   map[string]Response `json:"responses"`
}

type Parameter struct {
	Name        string `json:"name"`
	In          string `json:"in"` // "path", "query", "header"
	Required    bool   `json:"required"`
	Description string `json:"description,omitempty"`
	Schema      Schema `json:"schema"`
}

type RequestBody struct {
	Required bool                 `json:"required"`
	Content  map[string]MediaType `json:"content"`
}

type MediaType struct {
	Schema  Schema `json:"schema"`
	Example any    `json:"example,omitempty"`
}

type Schema struct {
	Ref         string            `json:"$ref,omitempty"`
	Type        string            `json:"type,omitempty"`
	Description string            `json:"description,omitempty"`
	Properties  map[string]Schema `json:"properties,omitempty"`
	Required    []string          `json:"required,omitempty"`
	Items       *Schema           `json:"items,omitempty"`
	Example     any               `json:"example,omitempty"`
}

type Components struct {
	Schemas         map[string]Schema         `json:"schemas,omitempty"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty"`
}

type SecurityScheme struct {
	Type         string `json:"type"`                   // "http"
	Scheme       string `json:"scheme"`                 // "bearer"
	BearerFormat string `json:"bearerFormat,omitempty"` // "JWT"
	Description  string `json:"description,omitempty"`
}

type Response struct {
	Description string `json:"description"`
}

// NewRefSchema 快捷构建组件引用 Schema
func NewRefSchema(refName string) Schema {
	return Schema{Ref: "#/components/schemas/" + refName}
}

// DefaultSecuritySchemes 返回开箱即用的 JWT Bearer 鉴权定义
func DefaultSecuritySchemes() map[string]SecurityScheme {
	return map[string]SecurityScheme{
		"BearerAuth": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
			Description:  "请输入登录后获取的 JWT Bearer Token 进行接口调用鉴权",
		},
	}
}
