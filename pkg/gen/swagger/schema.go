package swagger

import (
	"strings"
)

// StructDef 描述从源码 AST 中解析出的结构体元信息
type StructDef struct {
	Name   string
	Fields []StructField
}

// StructField 结构体单个字段描述
type StructField struct {
	Name     string // JSON 字段名
	Type     string // 字段类型 (如 string, int64, []int64, bool)
	Required bool   // 是否必填 (来自 binding:"required")
	Doc      string // 字段中文注释
}

// SchemaRegistry 结构体 Schema 注册中心与转换引擎
type SchemaRegistry struct {
	defs    map[string]*StructDef
	schemas map[string]Schema
}

func NewSchemaRegistry(defs map[string]*StructDef) *SchemaRegistry {
	return &SchemaRegistry{
		defs:    defs,
		schemas: make(map[string]Schema),
	}
}

// Resolve 解析或从缓存中获取结构体的 OpenAPI Schema 定义
func (r *SchemaRegistry) Resolve(typeName string) (Schema, bool) {
	if s, ok := r.schemas[typeName]; ok {
		return s, true
	}

	def, exists := r.defs[typeName]
	if !exists || len(def.Fields) == 0 {
		return Schema{}, false
	}

	props := make(map[string]Schema, len(def.Fields))
	var required []string

	for _, f := range def.Fields {
		prop := Schema{
			Example:     MockValue(f.Name, f.Type),
			Description: f.Doc,
		}

		if strings.HasPrefix(f.Type, "[]") {
			prop.Type = "array"
			elemType := strings.TrimPrefix(f.Type, "[]")
			prop.Items = &Schema{Type: ToOpenAPIType(elemType)}
		} else {
			prop.Type = ToOpenAPIType(f.Type)
		}

		props[f.Name] = prop
		if f.Required {
			required = append(required, f.Name)
		}
	}

	schema := Schema{
		Type:       "object",
		Properties: props,
		Required:   required,
		Example:    r.MockStructExample(def),
	}

	r.schemas[typeName] = schema
	return schema, true
}

// AllSchemas 获取当前所有已注册的结构体 Schema 字典
func (r *SchemaRegistry) AllSchemas() map[string]Schema {
	return r.schemas
}

// MockStructExample 为整个结构体生成开箱即用的 JSON 示例
func (r *SchemaRegistry) MockStructExample(def *StructDef) map[string]any {
	result := make(map[string]any, len(def.Fields))
	for _, f := range def.Fields {
		result[f.Name] = MockValue(f.Name, f.Type)
	}
	return result
}

// ToOpenAPIType 将 Go 原生类型映射为 OpenAPI 3.0 基本数据类型
func ToOpenAPIType(goType string) string {
	switch {
	case strings.Contains(goType, "int"):
		return "integer"
	case strings.Contains(goType, "float"):
		return "number"
	case goType == "bool":
		return "boolean"
	default:
		return "string"
	}
}

// MockValue 依据字段语义与数据类型生成逼真的示例数据
func MockValue(name, goType string) any {
	lower := strings.ToLower(name)

	// 1. 切片类型处理
	if strings.HasPrefix(goType, "[]") {
		elemType := strings.TrimPrefix(goType, "[]")
		if strings.Contains(elemType, "int") {
			return []int{1, 2, 3}
		}
		if strings.Contains(lower, "user") {
			return []string{"admin", "guest"}
		}
		if strings.Contains(lower, "id") {
			return []string{"id_001", "id_002"}
		}
		return []string{"item1", "item2"}
	}

	// 2. 布尔类型处理
	if goType == "bool" {
		return true
	}

	// 3. 数值类型处理
	if strings.Contains(goType, "int") || strings.Contains(goType, "float") {
		switch {
		case strings.Contains(lower, "limit"):
			return 10
		case strings.Contains(lower, "offset") || strings.Contains(lower, "page"):
			return 0
		case strings.Contains(lower, "status"):
			return 1
		case strings.Contains(lower, "id"):
			return 1
		default:
			return 0
		}
	}

	// 4. 字符串类型处理 (按常见业务词缀精准推导)
	switch {
	case strings.Contains(lower, "code"):
		return "admin"
	case strings.Contains(lower, "name") || strings.Contains(lower, "title"):
		return "示例名称"
	case strings.Contains(lower, "desc"):
		return "相关业务描述信息"
	case strings.Contains(lower, "email"):
		return "admin@example.com"
	case strings.Contains(lower, "phone") || strings.Contains(lower, "mobile"):
		return "13800138000"
	case strings.Contains(lower, "password"):
		return "Password123!"
	case strings.Contains(lower, "keyword"):
		return "search_key"
	default:
		return "string"
	}
}
