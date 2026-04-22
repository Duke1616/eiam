-- +goose Up
-- +goose StatementBegin
-- 录入两大核心角色：super_admin (系统极权，Type=2 隐藏)、admin (租户管理员，Type=1 共享)
-- 注意：tenant_id = 1 代表系统预置资源。
INSERT INTO `role` (`tenant_id`, `code`, `name`, `type`, `desc`, `inline_policies`, `ctime`, `utime`)
VALUES
    (1, 'super_admin', '系统超级管理员', 2,
     '平台最高管理权限，拥有跨租户治理、全局系统配置及底层基础设施的完全控制权。',
     '[{"name":"ROOT全量授权","code":"FullAccess","type":1,"statement":[{"effect":"Allow","action":["*"],"resource":["*"]}]}]',
     (UNIX_TIMESTAMP(NOW(3)) * 1000), (UNIX_TIMESTAMP(NOW(3)) * 1000)),
    (1, 'admin', '租户管理员', 1,
     '租户内最高管理权限，负责本租户内的资源管理、身份授权及安全治理，受限于平台全局合规性策略。',
     '[{"name":"全量授权","code":"AllAccess","type":1,"statement":[{"effect":"Allow","action":["*"],"resource":["*"]}]},{"name":"敏感权限熔断策略","code":"AdminStandard","type":1,"statement":[{"effect":"Deny","action":["iam:tenant:*","iam:permission:global:*"],"resource":["*"]}]}]',
     (UNIX_TIMESTAMP(NOW(3)) * 1000), (UNIX_TIMESTAMP(NOW(3)) * 1000))
    ON DUPLICATE KEY UPDATE
                         `name`            = VALUES(`name`),
                         `type`            = VALUES(`type`),
                         `desc`            = VALUES(`desc`),
                         `inline_policies` = VALUES(`inline_policies`),
                         `utime`           = VALUES(`utime`);

-- 初始化超级管理员账户：admin / 12345678
INSERT INTO `user` (`id`, `username`, `password`, `email`, `status`, `source`, `ctime`, `utime`)
VALUES (1, 'admin', '$2a$10$6ocvB6VX93BKFT4HruyWEOFy1ePGbXbd37uBvtnZ7CHovY9N3WotK', 'admin@example.com', 1, 'local',
        (UNIX_TIMESTAMP(NOW(3)) * 1000), (UNIX_TIMESTAMP(NOW(3)) * 1000))
ON DUPLICATE KEY UPDATE `password` = VALUES(`password`), `utime` = VALUES(`utime`);

-- 授予 admin 用户 super_admin 角色 (Domain 使用 '1')
INSERT INTO `casbin_rule` (`ptype`, `v0`, `v1`, `v2`)
VALUES ('g', 'user:admin', 'role:super_admin', '1')
ON DUPLICATE KEY UPDATE `v2` = VALUES(`v2`);

-- 初始化超级管理员的默认治理空间 (物理 ID 1)
INSERT INTO `tenant` (`id`, `name`, `code`, `domain`, `status`, `ctime`, `utime`)
VALUES (1, '系统根管理空间', 'system-root', 'localhost', 1,
        (UNIX_TIMESTAMP(NOW(3)) * 1000), (UNIX_TIMESTAMP(NOW(3)) * 1000))
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`), `code` = VALUES(`code`), `utime` = VALUES(`utime`);


-- 将超级管理员 admin 入驻到该空间中
-- 使得 admin 登录后能默认拥有 ID 为 1 的上下文
INSERT INTO `membership` (`tenant_id`, `user_id`, `ctime`)
VALUES (1, 1, (UNIX_TIMESTAMP(NOW(3)) * 1000))
ON DUPLICATE KEY UPDATE `tenant_id` = VALUES(`tenant_id`);

-- 初始化 admin 用户的个人名片（UserProfile）
INSERT INTO `user_profile` (`id`, `user_id`, `nickname`, `avatar`, `job_title`, `phone`)
VALUES (1, 1, '系统管理员', '', '平台负责人', '')
ON DUPLICATE KEY UPDATE `nickname` = VALUES(`nickname`), `job_title` = VALUES(`job_title`), `phone` = VALUES(`phone`);


-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM `role` WHERE `tenant_id` = 0 AND `code` IN ('super_admin', 'admin');
DELETE FROM `casbin_rule` WHERE `ptype` = 'g' AND `v0` = 'role:admin' AND `v1` = 'role:super_admin' AND `v2` = '0';
DELETE FROM `user` WHERE `username` = 'admin';
DELETE FROM `casbin_rule` WHERE `ptype` = 'g' AND `v0` = 'user:admin' AND `v1` = 'role:super_admin' AND `v2` = '0';
DELETE FROM `tenant` WHERE `id` = 1;

DELETE FROM `membership` WHERE `user_id` = 1 AND `tenant_id` = 1;
DELETE FROM `user_profile` WHERE `user_id` = 1;


-- +goose StatementEnd
