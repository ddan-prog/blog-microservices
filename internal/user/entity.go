package user

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID        uint64         `json:"id"`
	UUID      string         `json:"uuid"`
	Username  string         `json:"username"`
	Email     string         `json:"email"`
	Avatar    string         `json:"avatar"`
	Password  string         `json:"password"`
	Role      string         `json:"role"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at"`
}
