package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	// Handler function for the root path ("/")
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var loginRequest LoginRequest
		err := json.NewDecoder(r.Body).Decode(&loginRequest)
		if err != nil {
			http.Error(w, "Error parsing request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		connStr := "postgresql://postgres.lnwnzuvjzjpmixenztyg:[password]@fly-0-ewr.pooler.supabase.com:6543/postgres"
		db, err := sql.Open("postgres", connStr)
		rows, err := db.Query("SELECT * FROM AUTH_USER WHERE username = $1 AND password=$2", loginRequest.Username, loginRequest.Password)
		if err != nil {
			http.Error(w, "Error querying the database: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if !rows.Next() {
			http.Error(w, "Wrong username or password", http.StatusNotFound)
			return
		}

		var id, username, password, lastLogin, isSuperUser, firstName, lastName, email, isStaff, isActive, dateJoined string

		err = rows.Scan(&id, &password, &lastLogin, &isSuperUser, &username, &firstName, &lastName, &email, &isStaff, &isActive, &dateJoined)
		if err != nil {
			http.Error(w, "Error scanning the database: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":          id,
			"username":    username,
			"lastLogin":   lastLogin,
			"isSuperUser": isSuperUser,
			"firstName":   firstName,
			"lastName":    lastName,
			"email":       email,
			"isStaff":     isStaff,
			"isActive":    isActive,
			"dateJoined":  dateJoined,
			"nbf":         time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
		})
		tokenString, err := token.SignedString([]byte("potatosecret"))
		if err != nil {
			http.Error(w, "Error generating JWT: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token": "%s"}`, tokenString)
	})

	// Start the server listening on port 8080
	fmt.Println("Server listening on http://localhost:8080/")
	http.ListenAndServe(":8080", nil)
}
