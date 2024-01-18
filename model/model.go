package model

import (
	"gorm.io/gorm"
	"time"
)

type User struct {
	gorm.Model
	Username      string `gorm:"unique"`
	PasswordHash  []byte
	APIToken      string
	PasteContents []PasteContent
}

type PasteContent struct {
	gorm.Model
	Key             string `gorm:"unique;not null"`
	Content         []byte `gorm:"not null"`
	ContentType     string `gorm:"default:text/plain"`
	ContentLanguage string `gorm:"default:auto"`
	ValidTill       *time.Time
	Password        string
	UserId          uint
}
