# EIAM 全局工程规范与 AI 协作准则 (AGENTS.md)

EIAM 是企业级多租户 IAM 平台，基于 Casbin+OPA 双引擎鉴权、PBAC 数据范围约束与微服务资产自发现。

## 1. 架构分层与依赖单向流转铁律
$$\text{Transport (Web/gRPC)} \longrightarrow \text{Service} \longrightarrow \text{Repository} \longrightarrow \text{DAO / Storage}$$
- **Domain (`internal/domain/`)**：纯 Go 领域实体，严禁依赖 Transport 协议包或 GORM、Redis 等持久化框架。
- **Transport (`internal/web/`, `grpc/`)**：薄适配层，仅负责入参校验、上下文凭据提取并调用 Service。**严禁业务逻辑，严禁直接读写 DAO**。
- **Service (`internal/service/`)**：承载业务编排、策略计算、资产对账。禁止反向依赖 Transport。
- **Repository & DAO (`internal/repository/`)**：Repo 负责领域模型与实体转换及缓存策略；DAO 仅负责具体 SQL、事务控制与 GORM 操作。
- **SDK (`pkg/web/capability/`, `pkg/pbac/`)**：无侵入式契约与通用算法，**严禁反向依赖 `internal/` 私有业务包**。

## 2. 权限与多租户隔离原则
- **双引擎边界**：Casbin 仅维护角色层级图关系（`User -> Group -> Role`）；OPA 负责无状态 PBAC/ABAC 决策（AWS IAM 策略语法、AccessScope 计算、显式 Deny 优先）。
- **多租户安全 (Fail-Closed)**：
  - `gormx` 插件自动拦截多租户表。无租户上下文（`tid <= 0`）直接阻断 SQL 报错。
  - **显式提权出口**：初始化、资产对账、全局数据迁移必须显式调用 `ctx = gormx.IgnoreTenantContext(ctx)` 提权。
  - **双重租户上下文**：`tenant_id` 控制数据读写过滤边界；`origin_tenant_id` 为用户真实归属，用于权限判定，防跨租户提权。
- **资源 URN 唯一规范**：统一格式 `urn:iam:api:<service>:<method>:<path>` 和 `urn:iam:menu:<service>:<menu_code>`。

## 3. 事务一致性与并发安全
- **跨 DAO 事务原子性**：使用 Context 隐式传递统一的 `txKey`；DAO 获取事务连接时必须调用 `tx.WithContext(ctx)` 绑定最新上下文。
- **资产同步幂等性**：自发现扫描采用快照比对或基于业务键的 Upsert，确保重复执行幂等。

## 4. 编码规范与代码质量
- **命名规范**：
  - 接口必须以 `I` 开头（如 `IUserService`），实现结构体小写不导出（如 `userService`），构造函数为 `NewXxx`。
  - 变量/函数 `camelCase`，常量 `UPPER_SNAKE_CASE`，文件名 `kebab-case`。
- **注释与语言**：所有文档、说明交互**必须使用简体中文**；注释仅用于解释**“为什么这样设计”**（安全考量、架构权衡），严禁无意义复述代码。
- **现代 Go 语法**：优先使用标准库 `slices`，集合操作使用 `lo` / `ekit/slice`，避免编写冗长多层循环。
- **错误处理**：业务哨兵错误统一在 `internal/errs/error.go` 中定义；错误向上传递必须用 `fmt.Errorf("...: %w", err)` 附加上下文。

## 5. 构建工具链与测试约束
- **自动化工具链优先**：
  - 依赖管理：`go mod tidy`
  - Wire 依赖注入：新增/调整 Provider 后执行 `~/go/bin/wire ./ioc` 重新生成 `wire_gen.go`
  - 接口 Mock：接口变更后执行 `task mock`（生成代码统一收敛在包内 `mocks/`）
- **测试规范（强约束）**：
  - Service / Repo 单元测试统一采用**表驱动测试**（`testCases := []struct{...}`）；
  - 单元测试严禁直连外部生产资源；代码变更必须确保 `go test -race ./...` 竞态检测通过。
