// Package database provides database connection setup and auto-migration
// for the vulnerability database. It supports both PostgreSQL and SQLite.
package database

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"dependency-guardian/internal/config"
	"dependency-guardian/internal/vulndb/models"
)

// Open creates a new GORM database connection and runs auto-migration.
func Open(cfg config.VulnDBConfig, logger *slog.Logger) (*gorm.DB, error) {
	gormCfg := &gorm.Config{
		Logger: toGormLogLevel(cfg.LogLevel),
	}

	var db *gorm.DB
	var err error

	switch cfg.Driver {
	case "postgres", "postgresql":
		db, err = gorm.Open(postgres.Open(cfg.DSN), gormCfg)
	case "sqlite", "sqlite3":
		dsn := cfg.DSN
		// Append pragmas for WAL mode and busy timeout to avoid locks.
		if strings.Contains(dsn, "?") {
			dsn += "&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
		} else {
			dsn += "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
		}
		db, err = gorm.Open(sqlite.Open(dsn), gormCfg)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s (use 'postgres' or 'sqlite')", cfg.Driver)
	}

	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Configure connection pool.
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("getting underlying sql.DB: %w", err)
	}

	if cfg.Driver == "sqlite" || cfg.Driver == "sqlite3" {
		// SQLite only supports one writer at a time; using a single
		// connection avoids "database is locked" errors entirely.
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetConnMaxLifetime(0)
	} else {
		sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
		sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
		sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}

	// Run auto-migration.
	logger.Info("running database auto-migration")
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		return nil, fmt.Errorf("auto-migration failed: %w", err)
	}
	logger.Info("database migration complete", "driver", cfg.Driver)

	return db, nil
}

func toGormLogLevel(level string) gormlogger.Interface {
	switch level {
	case "silent":
		return gormlogger.Default.LogMode(gormlogger.Silent)
	case "error":
		return gormlogger.Default.LogMode(gormlogger.Error)
	case "info":
		return gormlogger.Default.LogMode(gormlogger.Info)
	default:
		return gormlogger.Default.LogMode(gormlogger.Warn)
	}
}
