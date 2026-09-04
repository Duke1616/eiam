package assets

import _ "embed"

// ServiceYAML 声明全平台逻辑微服务目录与元数据配置
//
//go:embed init/service.yaml
var ServiceYAML []byte

// MenuYAML 声明全平台初始化物理菜单树状结构
//
//go:embed init/menu.yaml
var MenuYAML []byte
