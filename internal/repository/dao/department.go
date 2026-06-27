package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Department struct {
	Id         int64                     `gorm:"type:bigint;primaryKey;autoIncrement;comment:'部门ID'"`
	TenantId   int64                     `gorm:"type:bigint;not null;default:0;uniqueIndex:uniq_idx_tenant_dept_name,priority:1;comment:'租户ID'"`
	ParentId   int64                     `gorm:"type:bigint;not null;default:0;index:idx_parent_id;comment:'父部门ID'"`
	Name       string                    `gorm:"type:varchar(255);not null;uniqueIndex:uniq_idx_tenant_dept_name,priority:2;comment:'部门名称'"`
	Sort       int64                     `gorm:"type:bigint;not null;default:0;comment:'排序号'"`
	Leaders    sqlx.JSONColumn[[]string] `gorm:"type:json;comment:'部门领导列表'"`
	MainLeader string                    `gorm:"type:varchar(64);not null;default:'';comment:'主负责人'"`
	Ctime      int64                     `gorm:"comment:'创建时间'"`
	Utime      int64                     `gorm:"comment:'更新时间'"`
}

type UserDepartment struct {
	Id           int64 `gorm:"type:bigint;primaryKey;autoIncrement"`
	TenantId     int64 `gorm:"type:bigint;not null;default:0;uniqueIndex:uniq_idx_tenant_user_dept,priority:1;comment:'租户ID'"`
	UserId       int64 `gorm:"type:bigint;not null;uniqueIndex:uniq_idx_tenant_user_dept,priority:2;comment:'用户ID'"`
	DepartmentId int64 `gorm:"type:bigint;not null;uniqueIndex:uniq_idx_tenant_user_dept,priority:3;comment:'部门ID'"`
	Ctime        int64 `gorm:"comment:'创建时间'"`
}

// IDepartmentDAO 部门数据访问对象接口
type IDepartmentDAO interface {
	// Insert 插入新部门
	Insert(ctx context.Context, d Department) (int64, error)
	// Update 更新部门基本信息
	Update(ctx context.Context, d Department) (int64, error)
	// Delete 删除部门
	Delete(ctx context.Context, id int64) error
	// GetByID 根据ID查询部门
	GetByID(ctx context.Context, id int64) (Department, error)
	// ListAll 查询全部部门
	ListAll(ctx context.Context) ([]Department, error)
	// ListByUserID 查询用户所在部门
	ListByUserID(ctx context.Context, userID int64) ([]Department, error)
	// CountChildren 统计部门下的子部门数量
	CountChildren(ctx context.Context, id int64) (int64, error)

	// 部门-用户关系

	// BindUsers 批量绑定部门成员关系
	BindUsers(ctx context.Context, bindings []UserDepartment) error
	// UnbindUsers 批量解绑部门成员关系
	UnbindUsers(ctx context.Context, deptID int64, userIDs []int64) error
	// ListMembers 分页查询部门成员列表，支持按关键字过滤
	ListMembers(ctx context.Context, deptID int64, offset, limit int64, keyword string) ([]User, int64, error)
	// CountMembers 获取部门成员数量
	CountMembers(ctx context.Context, deptID int64) (int64, error)
}

type departmentDAO struct {
	db *gorm.DB
}

func NewDepartmentDAO(db *gorm.DB) IDepartmentDAO {
	return &departmentDAO{db: db}
}

func (dao *departmentDAO) Insert(ctx context.Context, d Department) (int64, error) {
	now := time.Now().UnixMilli()
	d.Ctime = now
	d.Utime = now
	err := dao.db.WithContext(ctx).Create(&d).Error
	return d.Id, err
}

func (dao *departmentDAO) Update(ctx context.Context, d Department) (int64, error) {
	res := dao.db.WithContext(ctx).Model(&Department{}).
		Where("id = ?", d.Id).Updates(map[string]interface{}{
		"name":        d.Name,
		"parent_id":   d.ParentId,
		"sort":        d.Sort,
		"leaders":     d.Leaders,
		"main_leader": d.MainLeader,
		"utime":       time.Now().UnixMilli(),
	})
	return res.RowsAffected, res.Error
}

func (dao *departmentDAO) Delete(ctx context.Context, id int64) error {
	return dao.db.WithContext(ctx).Delete(&Department{}, id).Error
}

func (dao *departmentDAO) GetByID(ctx context.Context, id int64) (Department, error) {
	var d Department
	err := dao.db.WithContext(ctx).Where("id = ?", id).First(&d).Error
	return d, err
}

func (dao *departmentDAO) ListAll(ctx context.Context) ([]Department, error) {
	var ds []Department
	err := dao.db.WithContext(ctx).Order("sort ASC, ctime DESC").Find(&ds).Error
	return ds, err
}

func (dao *departmentDAO) ListByUserID(ctx context.Context, userID int64) ([]Department, error) {
	var ds []Department
	subQuery := dao.db.WithContext(ctx).Model(&UserDepartment{}).
		Where("user_id = ?", userID).
		Select("department_id")

	err := dao.db.WithContext(ctx).Model(&Department{}).
		Where("id IN (?)", subQuery).
		Order("sort ASC, ctime DESC").
		Find(&ds).Error
	return ds, err
}

func (dao *departmentDAO) CountChildren(ctx context.Context, id int64) (int64, error) {
	var count int64
	err := dao.db.WithContext(ctx).Model(&Department{}).Where("parent_id = ?", id).Count(&count).Error
	return count, err
}

func (dao *departmentDAO) BindUsers(ctx context.Context, bindings []UserDepartment) error {
	if len(bindings) == 0 {
		return nil
	}
	now := time.Now().UnixMilli()
	for i := range bindings {
		bindings[i].Ctime = now
	}
	return dao.db.WithContext(ctx).Clauses(clause.OnConflict{
		DoNothing: true,
	}).Create(&bindings).Error
}

func (dao *departmentDAO) UnbindUsers(ctx context.Context, deptID int64, userIDs []int64) error {
	if len(userIDs) == 0 {
		return nil
	}
	return dao.db.WithContext(ctx).Where("department_id = ? AND user_id IN ?", deptID, userIDs).Delete(&UserDepartment{}).Error
}

func (dao *departmentDAO) ListMembers(ctx context.Context, deptID int64, offset, limit int64, keyword string) ([]User, int64, error) {
	var (
		users []User
		total int64
	)

	subQuery := dao.db.WithContext(ctx).Model(&UserDepartment{}).
		Where("department_id = ?", deptID).
		Select("user_id")

	db := dao.db.WithContext(ctx).Model(&User{}).Where("id IN (?)", subQuery)
	if keyword != "" {
		db = db.Where("username LIKE ?", "%"+keyword+"%")
	}

	err := db.Count(&total).Error
	if err != nil || total == 0 {
		return nil, 0, err
	}

	err = db.Offset(int(offset)).Limit(int(limit)).Order("ctime DESC").Find(&users).Error
	return users, total, err
}

func (dao *departmentDAO) CountMembers(ctx context.Context, deptID int64) (int64, error) {
	var count int64
	err := dao.db.WithContext(ctx).Model(&UserDepartment{}).Where("department_id = ?", deptID).Count(&count).Error
	return count, err
}
