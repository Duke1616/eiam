package dao

// txKey 是 GORM 事务对象在 context.Context 中的统一键。
//
// NOTE: permRepo 和 resRepo 共享同一个 txKey，确保当外层（如 engine.Ingest）
// 开启一个跨 DAO 的事务时，两个 DAO 都能正确加入同一个数据库事务，
// 而不会各自独立开事务导致原子性被打破。
type txKey struct{}
