# EIAM - 企业级多租户身份治理与访问控制平台

EIAM 是面向微服务架构的企业级多租户统一身份与访问控制平台。系统基于 Casbin 与 OPA 双引擎架构构建，提供用户生命周期管理、多组织租户隔离、现代认证凭据以及基于属性的数据范围（PBAC）决策能力。

## 核心能力

### 多租户与组织管理
- 多租户强隔离：数据层原生拦截与上下文透传，支持租户安全切换与租户成员管理。
- 组织架构：支持无限级部门树、部门成员分配以及用户组角色继承。

### 现代认证体系
- 无密码登录：基于 WebAuthn 标准支持 Passkey 凭据注册与登录。
- 二次验证：内置基于时间的动态口令（TOTP MFA）多因素认证。
- 外部身份源：支持企业级 LDAP 用户检索与同步，以及标准 OIDC（含企业飞书）单点登录。

### 权限与数据范围决策
- 多维度策略绑定：遵循现代 IAM 规范，支持策略直接授予用户（User）、用户组继承（Group）以及角色关联（Role Attached / Inline）。
- RBAC 继承图计算：基于 Casbin 维护用户、组织组与角色的层级图关系，自动展开生效主体链。
- PBAC 细粒度与数据范围裁决：基于 OPA 执行统一策略裁决（AWS IAM 语法、显式 Deny 优先、Condition 上下文约束），并动态派生行级数据访问边界（AccessScope）。

### 资产自发现与契约工具链
- 权限资产治理：服务启动时自动扫描并同步本地受控权限资产。
- OpenAPI 3.0 文档：内置静态提取引擎，零注释导出 Swagger 规范并生成内嵌三栏式交互预览页面。
- 强类型契约代码：自动生成全系统权限点与领域模型常量，提供编译期类型检查。

## 鉴权架构与全链路流转

EIAM 采用 **Casbin（主体层级图计算） + OPA（统一策略与数据范围裁决）** 双引擎架构。系统支持 **用户直绑、组继承、角色关联及角色内联** 四维策略源，并由 OPA 统一执行权限放行与 `AccessScope` 行级数据范围计算。

全链路鉴权决策流转如下：

```mermaid
flowchart LR
    Client([业务请求]) --> Gateway[API 网关]

    %% 策略分支
    Gateway --> User[用户直绑]
    Gateway --> Casbin[Casbin 继承]
    Casbin --> Roles[组与角色]
    User --> Policies[生效策略集]
    Roles --> Policies

    %% 资源分支
    Gateway --> API[API 资产]
    API --> Actions[候选 Actions]

    %% OPA 决策
    Policies --> OPA{OPA 统一决策}
    Actions --> OPA

    %% 判定与落库
    OPA -->|拒绝| Deny([403 阻断])
    OPA -->|通过| Scope[AccessScope 约束]
    Scope --> Service[业务服务]
    Service --> DB[(GORM 租户隔离)]
    DB --> Response([受控响应])

    %% 极简主题配色
    classDef default fill:#ffffff,stroke:#94a3b8,stroke-width:1.5px,color:#1e293b
    classDef main fill:#f0fdf4,stroke:#16a34a,stroke-width:1.5px,color:#15803d
    classDef deny fill:#fef2f2,stroke:#dc2626,stroke-width:1.5px,color:#991b1b
    classDef accent fill:#f0f9ff,stroke:#0284c7,stroke-width:1.5px,color:#0369a1

    class Gateway,Policies,Actions,Service accent
    class OPA,Scope main
    class Deny deny
```

### 鉴权流转机制说明

1. **接入与上下文**：API 网关完成 Session 登录态校验，注入双租户上下文（数据过滤租户 `tenant_id` 与身份归属租户 `origin_tenant_id`）。
2. **多主体策略汇聚**：
   - 用户直接挂载的 Policy；
   - 通过 Casbin 继承图（`User -> Group -> Role`）解析出的关联组策略、角色关联策略及角色内联策略。
   - 所有策略汇总去重，生成当前主体全量的 **生效策略集（Effective Policies）**。
3. **资产与权限展开**：根据请求匹配物理 API 资产，并基于权限依赖树反向展开上级权限码，提取 **候选动作（Candidate Actions）**。
4. **OPA 统一裁决（PBAC）**：策略集、候选 Actions、资源 URN 与环境上下文统一输入 OPA 引擎：
   - 显式 Deny 优先阻断；未匹配任何 Allow 时默认隐式拒绝，均返回 **403 Forbidden**；
   - 命中 Allow 且满足 Condition 条件时放行，并动态求值派生 **AccessScope** 行级数据范围边界。
5. **业务执行与多租户原生隔离**：业务层消费 AccessScope 转换为参数化 SQL 过滤条件，数据持久层由 GORMx 插件实现底层无租户拦截（Fail-Closed 原生防越权）。

## 目录结构

```text
├── api                    # 协议契约：gRPC Proto 定义与 OpenAPI 3.0 文档
├── cmd                    # CLI 工具入口：server (主服务)、migrate (迁移)、permgen/swaggergen
├── config                 # 配置文件样例
├── docs                   # 系统架构指南、PBAC 数据范围说明与权限大盘字典
├── internal
│   ├── authz              # OPA / Rego 策略决策实现
│   ├── domain             # 业务领域实体定义
│   ├── grpc               # gRPC 远程服务实现
│   ├── repository         # 数据仓储层：DAO、GORM 持久化与缓存
│   ├── service            # 核心业务编排
│   └── web                # HTTP Handler 与请求模型
├── ioc                    # 基于 Wire 的依赖注入与基础设施初始化
├── migrations             # 启动自动执行的 SQL 迁移脚本
└── pkg                    # 共享工程包
    ├── contract           # 编译期强类型契约 (permission 权限码、model 领域模型)
    ├── gen                # 代码生成器引擎 (capability 权限生成器、swagger 文档生成器)
    ├── gormx              # 多租户隔离插件
    ├── pbac               # PBAC 策略评估引擎
    └── web                # Web 能力发现 SDK 与通用中间件
```

## 快速开始

### 1. 环境依赖

运行前请准备以下依赖：
- Go >= 1.25
- MySQL：业务数据存储与 Casbin 规则持久化
- Redis：缓存、Session 会话与分布式锁
- Etcd：服务注册与权限能力发现
- (可选) LDAP / OIDC：用于外部身份源联调

### 2. 配置文件

配置文件默认位于 `config/config.yaml`。可根据本地环境修改连接信息：

```yaml
web:
  host: "0.0.0.0"
  port: 9000

grpc:
  server:
    eiam:
      listen_addr: "0.0.0.0:8077"
      auth_token: "your-jwt-secret-key"

mysql:
  dsn: "root:password@tcp(127.0.0.1:3306)/eiam?charset=utf8mb4&parseTime=True&loc=Local"

redis:
  addr: "127.0.0.1:6379"

session:
  session_encrypted_key: "your-session-key"
  token_carrier: "token" # 可选: cookie 或 token
```

### 3. 启动服务

使用 Task 启动：

```bash
# 启动主服务 (自动执行表结构同步与数据迁移)
task run

# 或直接使用 Go 启动
go run main.go server
```

服务就绪后：
- HTTP API 端口：`http://localhost:9000`
- gRPC 服务端点：`localhost:8077`

## 常用开发命令

```bash
# 扫描全仓并刷新强类型权限契约与权限蓝图
task gen:perm

# 扫描路由并导出 OpenAPI 3.0 规范与交互式文档
task gen:swagger

# 生成 gRPC Proto 代码
task gen

# 执行单元测试
go test ./...
```

> **提示**：若本地未安装 `task` 命令，可直接使用原生 Go 命令替代，例如 `go run ./cmd/permgen`、`go run ./cmd/swaggergen`。

### 跨项目脚手架工具安装 (CLI Tooling)

EIAM 提供的权限契约生成器与 API 文档生成器已解耦为标准 CLI 工具。生态微服务（如 `etask`、`eflow` 等）可直接通过 `go install` 安装到本地使用，无需复制代码：

```bash
# 1. 安装权限 AST 扫描与强类型契约生成器 (permgen)
go install github.com/Duke1616/eiam/cmd/permgen@latest

# 2. 安装零注释 OpenAPI 3.0 与交互式预览生成器 (swaggergen)
go install github.com/Duke1616/eiam/cmd/swaggergen@latest

# 3. (可选) 安装 Taskfile 自动化任务调度工具
go install github.com/go-task/task/v3/cmd/task@latest
```

在下游微服务（如 `etask`）项目根目录中直接执行：

```bash
# 扫描当前微服务的 Handler 路由并导出强类型权限契约代码
permgen -s ./internal/web

# 导出标准的 OpenAPI 3.0 文档与交互式预览页面
swaggergen -s ./internal/web -o ./api/docs/swagger.json --html ./api/docs/index.html
```

### API 文档与联调

执行 `task gen:swagger`（或 `swaggergen`）后生成以下产物：
- OpenAPI 规范：`api/docs/swagger.json`，可导入 Apifox 或 Postman 进行联调。
- 交互式文档：在浏览器中直接打开 `api/docs/index.html`，支持在线调试与 Bearer Token 鉴权。

## 容器化构建与运行

构建镜像：

```bash
docker build -f deploy/Dockerfile -t eiam:latest .
```

运行容器：

```bash
docker run -d --name eiam \
  -v "$PWD/config/config.yaml:/app/config/config.yaml" \
  -p 9000:9000 \
  -p 8077:8077 \
  eiam:latest
```

## 相关文档

- [PBAC 策略与数据范围约束 (AccessScope)](docs/pbac-data-filter.md)
- [全平台权限矩阵大盘蓝图](docs/permissions.md)
