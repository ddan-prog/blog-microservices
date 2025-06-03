package user

type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
)

func (r UserRole) String() string {
	return string(r)
}

func (r UserRole) IsValid() bool {
	switch r {
	case RoleUser, RoleAdmin:
		return true
	default:
		return false
	}
}

func GetDefaultRole() UserRole {
	return RoleUser
}

func (u *User) IsAdmin() bool {
	return UserRole(u.Role) == RoleAdmin
}

func (u *User) IsUser() bool {
	return UserRole(u.Role) == RoleUser
}

func (u *User) SetRole(role UserRole) {
	u.Role = role.String()
}
