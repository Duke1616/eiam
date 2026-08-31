package swagger

import (
	"reflect"
	"strings"
)

// ReflectSchemaEngine 基于 Go 原生反射构建 OpenAPI 3.0 Schema 与智能 Example 的引擎
type ReflectSchemaEngine struct {
	cache map[reflect.Type]Schema
}

func NewReflectSchemaEngine() *ReflectSchemaEngine {
	return &ReflectSchemaEngine{
		cache: make(map[reflect.Type]Schema),
	}
}

// Generate 从任意 Go 类型或实例生成完整的 OpenAPI 3.0 Schema
func (e *ReflectSchemaEngine) Generate(v any) Schema {
	if v == nil {
		return Schema{Type: "object"}
	}

	t, ok := v.(reflect.Type)
	if !ok {
		t = reflect.TypeOf(v)
	}

	// 解引用指针
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if cached, exists := e.cache[t]; exists {
		return cached
	}

	schema := e.inspectType(t)
	e.cache[t] = schema
	return schema
}

func (e *ReflectSchemaEngine) inspectType(t reflect.Type) Schema {
	switch t.Kind() {
	case reflect.Struct:
		return e.inspectStruct(t)
	case reflect.Slice, reflect.Array:
		elemSchema := e.Generate(t.Elem())
		return Schema{
			Type:  "array",
			Items: &elemSchema,
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return Schema{Type: "integer", Example: 0}
	case reflect.Float32, reflect.Float64:
		return Schema{Type: "number", Example: 0.0}
	case reflect.Bool:
		return Schema{Type: "boolean", Example: true}
	default:
		return Schema{Type: "string", Example: "string"}
	}
}

func (e *ReflectSchemaEngine) inspectStruct(t reflect.Type) Schema {
	props := make(map[string]Schema, t.NumField())
	var required []string
	exampleMap := make(map[string]any, t.NumField())

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// 忽略未导出字段
		if !field.IsExported() {
			continue
		}

		// 解析 json tag
		jsonTag := field.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}

		fieldName := strings.Split(jsonTag, ",")[0]
		if fieldName == "" {
			fieldName = field.Name
		}

		// 解析 binding tag 判断是否必填
		bindingTag := field.Tag.Get("binding")
		if strings.Contains(bindingTag, "required") {
			required = append(required, fieldName)
		}

		// 递归解析字段类型
		fieldSchema := e.inspectType(field.Type)

		// 注入语义化 Mock 值
		mockVal := MockValueByReflect(fieldName, field.Type)
		fieldSchema.Example = mockVal
		props[fieldName] = fieldSchema
		exampleMap[fieldName] = mockVal
	}

	return Schema{
		Type:       "object",
		Properties: props,
		Required:   required,
		Example:    exampleMap,
	}
}

// MockValueByReflect 结合字段名与原生 reflect.Type 生成逼真的业务示例数据
func MockValueByReflect(name string, t reflect.Type) any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	lower := strings.ToLower(name)

	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		elemKind := t.Elem().Kind()
		if elemKind >= reflect.Int && elemKind <= reflect.Uint64 {
			return []int{1, 2, 3}
		}
		if strings.Contains(lower, "user") {
			return []string{"admin", "guest"}
		}
		if strings.Contains(lower, "id") {
			return []string{"id_001", "id_002"}
		}
		return []string{"item1", "item2"}

	case reflect.Bool:
		return true

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
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

	case reflect.Float32, reflect.Float64:
		return 0.0

	case reflect.String:
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

	default:
		return nil
	}
}
