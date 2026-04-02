package ioc

import (
	"github.com/gotomicro/ego/server/egin"
)

// App 模块化容器
type App struct {
	Web *egin.Component
}
