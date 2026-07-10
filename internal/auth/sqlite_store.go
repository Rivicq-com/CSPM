package auth

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type SqliteUserStore struct {
	db *sql.DB
}

func NewSqliteUserStore(dbPath string) (*SqliteUserStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA foreign_keys=ON")

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping sqlite: %w", err)
	}

	db.Exec(`CREATE TABLE IF NOT EXISTS tenants (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		domain TEXT UNIQUE NOT NULL,
		created_at TEXT DEFAULT (datetime('now')),
		updated_at TEXT DEFAULT (datetime('now'))
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL REFERENCES tenants(id),
		email TEXT UNIQUE NOT NULL,
		name TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		password_hash TEXT NOT NULL DEFAULT '',
		company TEXT DEFAULT '',
		avatar_url TEXT DEFAULT '',
		products TEXT DEFAULT '[]',
		github_id TEXT DEFAULT '',
		mfa_enabled INTEGER DEFAULT 0,
		mfa_secret TEXT,
		created_at TEXT DEFAULT (datetime('now')),
		updated_at TEXT DEFAULT (datetime('now'))
	)`)

	var tc int
	db.QueryRow("SELECT COUNT(*) FROM tenants").Scan(&tc)
	if tc == 0 {
		db.Exec("INSERT OR IGNORE INTO tenants (id, name, domain) VALUES (?, ?, ?)",
			"tenant-1", "Default Organization", "rivicq.de")
	}

	return &SqliteUserStore{db: db}, nil
}

func (s *SqliteUserStore) GetUserByEmail(email string) (*User, error) {
	var u User
	var mfaSecret sql.NullString
	err := s.db.QueryRow(
		`SELECT id, tenant_id, email, name, role, password_hash,
		        COALESCE(company,''), COALESCE(avatar_url,''), COALESCE(products,'[]'),
		        COALESCE(github_id,''), mfa_enabled, mfa_secret
		 FROM users WHERE email = ?`, strings.ToLower(email)).Scan(
		&u.ID, &u.TenantID, &u.Email, &u.Name, &u.Role, &u.Password,
		&u.Company, &u.AvatarURL, &u.Products, &u.GitHubID, &u.MFAEnabled, &mfaSecret,
	)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	if mfaSecret.Valid {
		u.MFASecret = mfaSecret.String
	}
	return &u, nil
}

func (s *SqliteUserStore) GetUserByID(id string) (*User, error) {
	var u User
	var mfaSecret sql.NullString
	err := s.db.QueryRow(
		`SELECT id, tenant_id, email, name, role, password_hash,
		        COALESCE(company,''), COALESCE(avatar_url,''), COALESCE(products,'[]'),
		        COALESCE(github_id,''), mfa_enabled, mfa_secret
		 FROM users WHERE id = ?`, id).Scan(
		&u.ID, &u.TenantID, &u.Email, &u.Name, &u.Role, &u.Password,
		&u.Company, &u.AvatarURL, &u.Products, &u.GitHubID, &u.MFAEnabled, &mfaSecret,
	)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	if mfaSecret.Valid {
		u.MFASecret = mfaSecret.String
	}
	return &u, nil
}

func (s *SqliteUserStore) CreateUser(user *User) error {
	hashed, err := HashPassword(user.Password)
	if err != nil {
		return err
	}
	user.ID = uuid.New().String()
	user.TenantID = "tenant-1"
	_, err = s.db.Exec(
		`INSERT INTO users (id, tenant_id, email, name, role, password_hash, company, avatar_url, products, github_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
		user.ID, user.TenantID, strings.ToLower(user.Email), user.Name, user.Role,
		hashed, user.Company, user.AvatarURL, user.Products, user.GitHubID,
	)
	return err
}

func (s *SqliteUserStore) UpdateUser(user *User) error {
	_, err := s.db.Exec(
		`UPDATE users SET name=?, role=?, company=?, avatar_url=?, products=?, github_id=?, updated_at=datetime('now')
		 WHERE id=?`,
		user.Name, user.Role, user.Company, user.AvatarURL, user.Products, user.GitHubID, user.ID,
	)
	return err
}

func (s *SqliteUserStore) Close() error {
	return s.db.Close()
}
