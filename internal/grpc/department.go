package grpc

import (
	"context"

	departmentv1 "github.com/Duke1616/eiam/api/proto/gen/eiam/department/v1"
	userv1 "github.com/Duke1616/eiam/api/proto/gen/eiam/user/v1"
	"github.com/Duke1616/eiam/internal/domain"
	departmentsvc "github.com/Duke1616/eiam/internal/service/department"
	"github.com/ecodeclub/ekit/slice"
	"github.com/gotomicro/ego/core/elog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DepartmentServer struct {
	departmentv1.UnimplementedDepartmentServiceServer

	svc departmentsvc.IDepartmentService
}

func NewDepartmentServer(svc departmentsvc.IDepartmentService) departmentv1.DepartmentServiceServer {
	return &DepartmentServer{
		svc: svc,
	}
}

func (s *DepartmentServer) QueryByUserId(ctx context.Context, req *departmentv1.QueryByUserIdReq) (*departmentv1.QueryDepartmentsResp, error) {
	if req.GetUserId() <= 0 {
		return &departmentv1.QueryDepartmentsResp{
			ErrorCode:    departmentv1.ErrorCode_INVALID_PARAMETER,
			ErrorMessage: "user_id 必须大于 0",
		}, nil
	}

	departments, err := s.svc.ListByUserID(ctx, req.GetUserId())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	return &departmentv1.QueryDepartmentsResp{
		Departments: slice.Map(departments, func(idx int, src domain.Department) *departmentv1.Department {
			return s.toDepartmentProto(src)
		}),
	}, nil
}

func (s *DepartmentServer) ListMembers(ctx context.Context, req *departmentv1.ListMembersReq) (*departmentv1.ListMembersResp, error) {
	if req.GetDepartmentId() <= 0 {
		return &departmentv1.ListMembersResp{
			ErrorCode:    departmentv1.ErrorCode_INVALID_PARAMETER,
			ErrorMessage: "department_id 必须大于 0",
		}, nil
	}
	if req.GetOffset() < 0 {
		return &departmentv1.ListMembersResp{
			ErrorCode:    departmentv1.ErrorCode_INVALID_PARAMETER,
			ErrorMessage: "offset 不能小于 0",
		}, nil
	}

	limit := req.GetLimit()
	if limit <= 0 {
		limit = 20
	}

	members, total, err := s.svc.ListMembers(ctx, req.GetDepartmentId(), req.GetOffset(), limit, req.GetKeyword())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	return &departmentv1.ListMembersResp{
		Members: slice.Map(members, func(idx int, src domain.User) *userv1.User {
			return s.toUserProto(src, req.GetDepartmentId())
		}),
		Total: total,
	}, nil
}

func (s *DepartmentServer) toDepartmentProto(src domain.Department) *departmentv1.Department {
	return &departmentv1.Department{
		Id:         src.ID,
		ParentId:   src.ParentID,
		Name:       src.Name,
		Sort:       src.Sort,
		Leaders:    src.Leaders,
		MainLeader: src.MainLeader,
		Ctime:      src.Ctime,
		Utime:      src.Utime,
	}
}

func (s *DepartmentServer) toUserProto(src domain.User, departmentID int64) *userv1.User {
	user := &userv1.User{
		Id:           src.ID,
		Username:     src.Username,
		DisplayName:  src.Profile.Nickname,
		Email:        src.Email,
		Phone:        src.Profile.Phone,
		DepartmentId: departmentID,
	}

	if lark, ok := src.GetPrimaryIdentity("feishu"); ok {
		user.LarkUserId = lark.IdentityKey()
	}

	if wechat, ok := src.GetPrimaryIdentity("wechat"); ok {
		user.WechatUserId = wechat.IdentityKey()
	}

	return user
}

func (s *DepartmentServer) toGRPCError(err error) error {
	if err == nil {
		return nil
	}

	if _, ok := status.FromError(err); ok {
		return err
	}

	elog.DefaultLogger.Error("gRPC 接口遭遇系统内部未知异常", elog.FieldErr(err))
	return status.Error(codes.Internal, "服务器内部错误")
}
