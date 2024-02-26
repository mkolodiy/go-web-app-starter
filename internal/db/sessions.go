package db

import (
	"database/sql"
	"time"
)

type Session struct {
	ID        int64     `db:"id"`
	SessionID string    `db:"session_id"`
	UserID    int64     `db:"user_id"`
	Expires   time.Time `db:"expires"`
}

func InsertSession(db *sql.DB, session Session) error {
	_, err := db.Exec("INSERT INTO sessions VALUES(NULL,?,?,?);", session.SessionID, session.UserID, session.Expires.Unix())
	if err != nil {
		return err
	}
	return nil
}

func GetSessionByUserID(db *sql.DB, userID int64) (*Session, error) {
	var expires int64
	row := db.QueryRow("SELECT * FROM sessions WHERE user_id = ?;", userID)
	var session Session
	err := row.Scan(&session.ID, &session.SessionID, &session.UserID, &expires)
	if err != nil {
		return nil, err
	}
	session.Expires = time.Unix(expires, 0)
	return &session, nil
}

func GetSession(db *sql.DB, sessionID string) (*Session, error) {
	var expires int64
	row := db.QueryRow("SELECT * FROM sessions WHERE session_id = ?;", sessionID)
	var session Session
	err := row.Scan(&session.ID, &session.SessionID, &session.UserID, &expires)
	if err != nil {
		return nil, err
	}
	session.Expires = time.Unix(expires, 0)
	return &session, nil
}

func RemoveSession(db *sql.DB, sessionID string) error {
	_, err := db.Exec("DELETE FROM sessions WHERE session_id = ?;", sessionID)
	return err
}
