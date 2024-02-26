package db

import "database/sql"

type User struct {
	ID        int64  `db:"id"`
	FirstName string `db:"first_name"`
	LastName  string `db:"last_name"`
	Email     string `db:"email"`
	Password  string `db:"password"`
}

func InsertUser(db *sql.DB, user User) (int64, error) {
	res, err := db.Exec("INSERT INTO users VALUES(NULL,?,?,?,?);", user.FirstName, user.LastName, user.Email, user.Password)
	if err != nil {
		return -1, err
	}
	return res.LastInsertId()
}

func GetUserByEmail(db *sql.DB, email string) (*User, error) {
	row := db.QueryRow("SELECT * FROM users WHERE email = ?;", email)
	var user User
	err := row.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
