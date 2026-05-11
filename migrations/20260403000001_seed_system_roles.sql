-- +goose Up
-- +goose StatementBegin
-- 录入两大核心角色：super_admin (系统极权，Type=2 隐藏)、admin (租户管理员，Type=1 共享)
-- 注意：tenant_id = 1 代表系统预置资源。
INSERT INTO `role` (`tenant_id`, `code`, `name`, `type`, `desc`, `inline_policies`, `ctime`, `utime`)
VALUES
    (1, 'super_admin', '系统超级管理员', 2,
     '平台最高管理权限，拥有跨租户治理、全局系统配置及底层基础设施的完全控制权。',
     '[{"name":"ROOT全量授权","code":"FullAccess","type":1,"statement":[{"effect":"Allow","action":["*"],"resource":["*"]}]}]',
     FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000), FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000)),
    (1, 'admin', '租户管理员', 1,
     '租户内最高管理权限，负责本租户内的资源管理、身份授权及安全治理。安全边界由系统 Boundary 机制自动约束，禁止访问跨租户或系统级资源。',
     '[{"name":"租户内全量授权","code":"TenantAllAccess","type":1,"statement":[{"effect":"Allow","action":["*"],"resource":["*"]}]}]',
     FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000), FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000))
    ON DUPLICATE KEY UPDATE
                         `name`            = VALUES(`name`),
                         `type`            = VALUES(`type`),
                         `desc`            = VALUES(`desc`),
                         `inline_policies` = VALUES(`inline_policies`),
                         `utime`           = VALUES(`utime`);

-- 初始化超级管理员账户：admin / 12345678
INSERT INTO `user` (`id`, `username`, `password`, `email`, `status`, `source`, `ctime`, `utime`)
VALUES (1, 'admin', '$2a$10$6ocvB6VX93BKFT4HruyWEOFy1ePGbXbd37uBvtnZ7CHovY9N3WotK', 'admin@example.com', 1, 'local',
        FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000), FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000))
ON DUPLICATE KEY UPDATE `password` = VALUES(`password`), `utime` = VALUES(`utime`);

-- 授予 admin 用户 super_admin 角色 (Domain 使用 '1'，v3 记录授权时间)
INSERT INTO `casbin_rule` (`ptype`, `v0`, `v1`, `v2`, `v3`)
VALUES ('g', 'user:admin', 'role:super_admin', '1', FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000))
ON DUPLICATE KEY UPDATE `v2` = VALUES(`v2`), `v3` = VALUES(`v3`);

-- 初始化超级管理员的默认治理空间 (物理 ID 1)
INSERT INTO `tenant` (`id`, `name`, `code`, `domain`, `status`, `ctime`, `utime`)
VALUES (1, '系统根管理空间', 'system-root', 'localhost', 1,
        FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000), FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000))
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`), `code` = VALUES(`code`), `utime` = VALUES(`utime`);


-- 将超级管理员 admin 入驻到该空间中
-- 使得 admin 登录后能默认拥有 ID 为 1 的上下文
INSERT INTO `membership` (`tenant_id`, `user_id`, `ctime`)
VALUES (1, 1, FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000))
ON DUPLICATE KEY UPDATE `tenant_id` = VALUES(`tenant_id`);

-- 初始化 admin 用户的个人名片（UserProfile）
INSERT INTO `user_profile` (`id`, `user_id`, `nickname`, `avatar`, `job_title`, `phone`)
VALUES (1, 1, '系统管理员', '', '平台负责人', '')
ON DUPLICATE KEY UPDATE `nickname` = VALUES(`nickname`), `job_title` = VALUES(`job_title`), `phone` = VALUES(`phone`);

-- 初始化系统预置身份源：本地口令 (默认启用)
INSERT INTO `identity_source` (`id`, `name`, `type`, `local_config`, `enabled`, `ctime`, `utime`)
VALUES (1, '本地账号登录', 'local', '{"min_length": 6, "max_failed_attempts": 5, "lockout_duration": 15}', 1,
        FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000), FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000))
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`), `enabled` = VALUES(`enabled`), `utime` = VALUES(`utime`);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM `role` WHERE `tenant_id` = 1 AND `code` IN ('super_admin', 'admin');
DELETE FROM `casbin_rule` WHERE `ptype` = 'g' AND `v0` = 'role:admin' AND `v1` = 'role:super_admin' AND `v2` = '1';
DELETE FROM `user` WHERE `username` = 'admin';
DELETE FROM `casbin_rule` WHERE `ptype` = 'g' AND `v0` = 'user:admin' AND `v1` = 'role:super_admin' AND `v2` = '1';
DELETE FROM `tenant` WHERE `id` = 1;

DELETE FROM `membership` WHERE `user_id` = 1 AND `tenant_id` = 1;
DELETE FROM `user_profile` WHERE `user_id` = 1;
DELETE FROM `identity_source` WHERE `id` = 1;


-- +goose StatementEnd
