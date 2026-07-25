package pbac

import "time"

const (
	PrincipalUsername      AttributeKey = "principal:username"
	EnvironmentCurrentTime AttributeKey = "environment:current_time"
)

// PrincipalAttributes 保存由 EIAM 已验证身份产生的主体属性。
type PrincipalAttributes struct {
	Username string
}

// EnvironmentAttributes 保存由 EIAM 服务端生成的环境属性。
type EnvironmentAttributes struct {
	CurrentTime time.Time
}

// EvaluationContext 汇总一次授权决策中可信的立即求值属性。
type EvaluationContext struct {
	Principal   PrincipalAttributes
	Environment EnvironmentAttributes
}

// Attributes 将可信上下文转换为 Condition evaluator 使用的属性集合。
func (c EvaluationContext) Attributes() map[AttributeKey]any {
	result := map[AttributeKey]any{
		PrincipalUsername: c.Principal.Username,
	}
	if !c.Environment.CurrentTime.IsZero() {
		result[EnvironmentCurrentTime] = c.Environment.CurrentTime.UTC().Format(time.RFC3339)
	}
	return result
}

var immediateAttributeKeys = map[AttributeKey]struct{}{
	PrincipalUsername:      {},
	EnvironmentCurrentTime: {},
}

func isImmediateAttribute(key AttributeKey) bool {
	_, ok := immediateAttributeKeys[key]
	return ok
}
