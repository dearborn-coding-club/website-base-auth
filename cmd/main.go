package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Config struct {
	Password   string `env:"SUPABASE_POSTGRESQL_PASSWORD,required"`
	HmacSecret string `env:"HMAC_SECRET,required"`
}

func GenerateRefreshToken() (string, error) {
	// Create a byte slice for random data
	randomBytes := make([]byte, 32) // 32 bytes = 256 bits

	// Fill the slice with random bytes
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode the bytes to a base64 URL-safe string
	refreshToken := base64.URLEncoding.EncodeToString(randomBytes)

	return refreshToken, nil
}

func main() {
	// Handler function for the root path ("/")
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var cfg Config
		err := env.Parse(&cfg)

		var loginRequest LoginRequest
		err = json.NewDecoder(r.Body).Decode(&loginRequest)
		if err != nil {
			http.Error(w, "Error parsing request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		connStr := fmt.Sprintf("postgresql://postgres.lnwnzuvjzjpmixenztyg:%s@fly-0-ewr.pooler.supabase.com:6543/postgres", cfg.Password)
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
		refreshToken, err := GenerateRefreshToken()
		if err != nil {
			http.Error(w, "Error generating refresh token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token": "%s", "refresh_token": "%s"}`, tokenString, refreshToken)

	})

	// Start the server listening on port 8080
	fmt.Println("Server listening on http://localhost:8080/")
	http.ListenAndServe(":8080", nil)
}
