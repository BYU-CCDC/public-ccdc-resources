package models

import (
	"time"

	"gorm.io/gorm"
)

const (
	TypeYaraFinding  = "yara_rule:finding"
	TypeSigmaFinding = "sigma_alert:finding" // Added type constant for Sigma
)

// SigmaAlertFinding represents a Sigma alert finding in the database.
type SigmaAlertFinding struct {
	ID          uint      `gorm:"primaryKey;autoIncrement"` // Ensure auto-increment for ID
	AlertID     string    `gorm:"not null"`                 // Sigma alert ID
	AlertName   string    `gorm:"not null"`                 // Name of the Sigma alert
	CommandArgs string    `gorm:"not null"`                 // Command arguments related to the alert
	Image       string    `gorm:"not null"`                 // Process image
	EventTime   time.Time `gorm:"index"`                    // Index for faster lookups
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

// YaraFinding represents a YARA detection in the database.
type YaraFinding struct {
	ID           uint      `gorm:"primaryKey;autoIncrement"` // Ensure auto-increment for ID
	FileLocation string    `gorm:"not null"`
	YaraRuleName string    `gorm:"not null"`
	EventTime    time.Time `gorm:"index"` // Index for faster lookups
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}
