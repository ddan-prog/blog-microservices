package middleware

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
)

type RoleContext struct {
	UserID uint64
	Role   UserRole
}

type contextKey string

const roleContextKey contextKey = "role"

func WithRole(ctx context.Context, userID uint64, role UserRole) context.Context {
	return context.WithValue(ctx, roleContextKey, &RoleContext{
		UserID: userID,
		Role:   role,
	})
}

func GetRoleFromContext(ctx context.Context) (*RoleContext, bool) {
	role, ok := ctx.Value(roleContextKey).(*RoleContext)
	return role, ok
}

func RequireRole(requiredRole UserRole) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		roleCtx, ok := GetRoleFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "role information not found")
		}

		if roleCtx.Role != requiredRole && roleCtx.Role != RoleAdmin {
			return nil, status.Error(codes.PermissionDenied, fmt.Sprintf("required role: %s, current role: %s", requiredRole, roleCtx.Role))
		}

		return handler(ctx, req)
	}
}

func RequireAdmin() grpc.UnaryServerInterceptor {
	return RequireRole(RoleAdmin)
}

func ExtractRoleFromMetadata() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return handler(ctx, req)
		}

		userIDs := md.Get("user-id")
		roles := md.Get("user-role")

		if len(userIDs) > 0 && len(roles) > 0 {
			var userID uint64
			fmt.Sscanf(userIDs[0], "%d", &userID)
			role := UserRole(roles[0])

			ctx = WithRole(ctx, userID, role)
		}

		return handler(ctx, req)
	}
}
