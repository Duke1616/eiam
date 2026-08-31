package capability

import (
	"fmt"
	"math"
	"strings"
)

// Validator 权限依赖图静态合法性校验器
type Validator struct{}

// NewValidator 创建校验器
func NewValidator() *Validator {
	return &Validator{}
}

// Validate 对全局权限图进行全面诊断
func (v *Validator) Validate(g *Graph) []Issue {
	var issues []Issue
	issues = append(issues, v.checkDangling(g)...)
	issues = append(issues, v.checkCycles(g)...)
	return issues
}

// checkDangling 检查是否存在未定义的悬空依赖
func (v *Validator) checkDangling(g *Graph) []Issue {
	var issues []Issue

	for _, act := range g.Actions {
		for _, dep := range act.Needs {
			if _, exists := g.Actions[dep]; exists {
				continue
			}

			// 外部微服务依赖（如 cmdb:*）视为合法外部契约
			if !strings.HasPrefix(dep, act.Service+":") {
				continue
			}

			suggestion := v.suggestSimilar(dep, g.Actions)
			issues = append(issues, Issue{
				Severity:   "ERROR",
				File:       act.File,
				Line:       act.Line,
				ActionCode: act.Code,
				Message:    fmt.Sprintf("权限点 [%s] 声明的前置依赖 [%s] 在系统内未找到", act.Code, dep),
				Suggestion: suggestion,
			})
		}
	}

	return issues
}

// checkCycles 使用三色标记法检测是否存在循环死锁依赖
func (v *Validator) checkCycles(g *Graph) []Issue {
	var issues []Issue
	colors := make(map[string]int) // 0: 白(未访问), 1: 灰(栈中), 2: 黑(已完成)

	var dfs func(code string, path []string)
	dfs = func(code string, path []string) {
		colors[code] = 1
		path = append(path, code)

		if act, ok := g.Actions[code]; ok {
			for _, dep := range act.Needs {
				if colors[dep] == 1 {
					cycle := strings.Join(append(path, dep), " -> ")
					issues = append(issues, Issue{
						Severity:   "ERROR",
						File:       act.File,
						Line:       act.Line,
						ActionCode: act.Code,
						Message:    fmt.Sprintf("发现循环依赖闭环: %s", cycle),
					})
				} else if colors[dep] == 0 {
					dfs(dep, path)
				}
			}
		}

		colors[code] = 2
	}

	for code := range g.Actions {
		if colors[code] == 0 {
			dfs(code, nil)
		}
	}

	return issues
}

// suggestSimilar 利用编辑距离找出最相近的已知权限码
func (v *Validator) suggestSimilar(target string, actions map[string]*Action) string {
	best := ""
	minDist := math.MaxInt32

	for code := range actions {
		d := distance(target, code)
		if d < minDist && d <= 5 {
			minDist = d
			best = code
		}
	}

	if best != "" {
		return fmt.Sprintf("猜你想引用的是: [%s]", best)
	}
	return ""
}

func distance(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	n, m := len(r1), len(r2)
	if n == 0 {
		return m
	}
	if m == 0 {
		return n
	}

	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
		dp[i][0] = i
	}
	for j := 0; j <= m; j++ {
		dp[0][j] = j
	}

	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}
			dp[i][j] = min(
				dp[i-1][j]+1,
				dp[i][j-1]+1,
				dp[i-1][j-1]+cost,
			)
		}
	}

	return dp[n][m]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
