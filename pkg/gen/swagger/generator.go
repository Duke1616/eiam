package swagger

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
)

//go:embed templates/index.html.tmpl
var indexHTMLTemplate string

var htmlTmpl = template.Must(template.New("scalar_index").Parse(indexHTMLTemplate))

// Generator 负责将提取出的 API 元数据装配为 OpenAPI 3.0 规范并导出文档
type Generator struct {
	Title   string
	Version string
}

func NewGenerator(title, version string) *Generator {
	if title == "" {
		title = "EIAM API Documentation"
	}
	if version == "" {
		version = "1.0.0"
	}
	return &Generator{Title: title, Version: version}
}

// Generate 装配端点并导出 swagger.json 与 Scalar 预览页面
func (g *Generator) Generate(endpoints []Endpoint, structs map[string]*StructDef, jsonPath, htmlPath string) error {
	registry := NewSchemaRegistry(structs)
	doc := g.assembleSpec(endpoints, registry)

	// 1. 导出规范 JSON
	jsonData, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 OpenAPI 规范失败: %w", err)
	}

	if err = os.MkdirAll(filepath.Dir(jsonPath), 0755); err != nil {
		return err
	}
	if err = os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("写入规范文件 %s 失败: %w", jsonPath, err)
	}

	// 2. 导出现代化三栏式预览网页
	if htmlPath != "" {
		if err = os.MkdirAll(filepath.Dir(htmlPath), 0755); err != nil {
			return err
		}
		htmlContent, err := g.renderHTML(jsonData)
		if err != nil {
			return err
		}
		if err = os.WriteFile(htmlPath, []byte(htmlContent), 0644); err != nil {
			return fmt.Errorf("写入预览页面 %s 失败: %w", htmlPath, err)
		}
	}

	return nil
}

func (g *Generator) assembleSpec(endpoints []Endpoint, registry *SchemaRegistry) Spec {
	doc := Spec{
		OpenAPI: "3.0.0",
		Info: Info{
			Title:       g.Title,
			Description: "基于 AST 与反射契约混合自适应生成的 OpenAPI 3.0 规范，支持导入 Apifox / Postman 进行全量接口联调。",
			Version:     g.Version,
		},
		Security: []SecurityRequirement{
			{"BearerAuth": {}},
		},
		Paths: make(map[string]PathItem),
		Components: &Components{
			Schemas:         make(map[string]Schema),
			SecuritySchemes: DefaultSecuritySchemes(),
		},
	}

	tagsMap := make(map[string]bool)

	for _, ep := range endpoints {
		normPath, pathParams := normalizePathAndExtractParams(ep.Path)
		pathItem, ok := doc.Paths[normPath]
		if !ok {
			pathItem = make(PathItem)
		}

		op := Operation{
			Summary:     ep.Summary,
			Description: ep.Description,
			Tags:        []string{ep.Tag},
			Parameters:  pathParams,
			Responses: map[string]Response{
				"200": {Description: "请求成功"},
			},
		}

		if ep.Tag != "" {
			tagsMap[ep.Tag] = true
		}

		// 处理请求入参模型
		if ep.ReqType != "" {
			schema, exists := registry.Resolve(ep.ReqType)
			if exists {
				doc.Components.Schemas[ep.ReqType] = schema
			}

			if ep.Method == "GET" {
				// GET 请求展开为 Query 参数
				if exists {
					for name, prop := range schema.Properties {
						op.Parameters = append(op.Parameters, Parameter{
							Name:        name,
							In:          "query",
							Required:    slices.Contains(schema.Required, name),
							Description: prop.Description,
							Schema:      prop,
						})
					}
				}
			} else {
				// POST/PUT/DELETE 请求挂载 RequestBody
				media := MediaType{
					Schema: NewRefSchema(ep.ReqType),
				}
				if exists {
					media.Example = schema.Example
				}
				op.RequestBody = &RequestBody{
					Required: true,
					Content: map[string]MediaType{
						"application/json": media,
					},
				}
			}
		}

		methodKey := strings.ToLower(ep.Method)
		pathItem[methodKey] = op
		doc.Paths[normPath] = pathItem
	}

	// 整理 Tags 分组并字母排序
	for tag := range tagsMap {
		doc.Tags = append(doc.Tags, Tag{Name: tag})
	}
	slices.SortFunc(doc.Tags, func(a, b Tag) int {
		return strings.Compare(a.Name, b.Name)
	})

	return doc
}

func (g *Generator) renderHTML(jsonData []byte) (string, error) {
	var buf bytes.Buffer
	data := struct {
		Title    string
		SpecJSON string
	}{
		Title:    g.Title,
		SpecJSON: string(jsonData),
	}
	if err := htmlTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("渲染 Scalar HTML 模板失败: %w", err)
	}
	return buf.String(), nil
}

func normalizePathAndExtractParams(rawPath string) (string, []Parameter) {
	var params []Parameter
	parts := strings.Split(rawPath, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, ":") {
			paramName := strings.TrimPrefix(part, ":")
			parts[i] = "{" + paramName + "}"

			p := Parameter{
				Name:     paramName,
				In:       "path",
				Required: true,
			}
			lower := strings.ToLower(paramName)
			if strings.Contains(lower, "id") {
				p.Description = "唯一数字标识 ID"
				p.Schema = Schema{Type: "integer", Example: 1}
			} else if strings.Contains(lower, "code") {
				p.Description = "唯一标识编码 Code"
				p.Schema = Schema{Type: "string", Example: "admin"}
			} else {
				p.Description = "路径参数"
				p.Schema = Schema{Type: "string", Example: paramName}
			}
			params = append(params, p)
		}
	}
	return strings.Join(parts, "/"), params
}
