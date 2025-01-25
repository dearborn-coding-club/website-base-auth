package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
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

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
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

func handlePreflight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

func main() {
	http.HandleFunc("/validate-token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			handlePreflight(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodOptions {
			handlePreflight(w, r)
			return
		}
		var cfg Config
		err := env.Parse(&cfg)
		if err != nil {
			http.Error(w, "Error parsing environment variables: "+err.Error(), http.StatusInternalServerError)
			return
		}
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "No token provided", http.StatusUnauthorized)
			return
		}

		tokenString = tokenString[7:]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte("potatosecret"), nil
		})
		if err != nil {
			http.Error(w, "Error parsing JWT: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Error parsing claims", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, `{"claims": %v}`, claims)
	})

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			handlePreflight(w, r)
			return
		}

		var cfg Config
		err := env.Parse(&cfg)
		if err != nil {
			http.Error(w, "could build config"+err.Error(), http.StatusInternalServerError)
			return
		}
		var registerRequest RegisterRequest
		err = json.NewDecoder(r.Body).Decode(&registerRequest)
		if err != nil {
			http.Error(w, "Unable to decode response: "+err.Error(), http.StatusInternalServerError)
		}

		connStr := fmt.Sprintf("postgresql://postgres.lnwnzuvjzjpmixenztyg:%s@fly-0-ewr.pooler.supabase.com:6543/postgres", cfg.Password)
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			http.Error(w, "Error parsing request body: "+err.Error(), http.StatusNotFound)
			return
		}

		rows, err := db.Query("SELECT * FROM ACCOUNTS_DCCUSER WHERE USERNAME = $1", registerRequest.Username)

		if err != nil {
			http.Error(w, "Error selecting from database: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if rows.Next() {
			http.Error(w, "User already exists"+err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO ACCOUNTS_DCCUSER (username, password, email, is_superuser, first_name, last_name, is_staff, is_active, date_joined, bio, birthdate, profile_id, last_login) VALUES ($1, $2, $3, FALSE, 'test_name', 'test_name', FALSE, FALSE, '2017-03-14', 'test-bio', '2017-03-14', 1, '2017-03-14')", registerRequest.Username, registerRequest.Password, registerRequest.Email)

		if err != nil {
			http.Error(w, "Error querying the database: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{ 'generated': true }")
	})

	// Handler function for the root path ("/")
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			handlePreflight(w, r)
			return
		}
		var cfg Config
		err := env.Parse(&cfg)
		refreshToken, err := GenerateRefreshToken()
		var loginRequest LoginRequest
		err = json.NewDecoder(r.Body).Decode(&loginRequest)
		if err != nil {
			http.Error(w, "Unable to decode response: "+err.Error(), http.StatusInternalServerError)
			return
		}
		connStr := fmt.Sprintf("postgresql://postgres.lnwnzuvjzjpmixenztyg:%s@fly-0-ewr.pooler.supabase.com:6543/postgres", cfg.Password)
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			log.Fatalf("Unable to execute query: %v\n", err)
		}
		rows, err := db.Query("SELECT * FROM ACCOUNTS_DCCUSER WHERE username = $1 AND password=$2", loginRequest.Username, loginRequest.Password)

		if err != nil {
			log.Fatalf("Unable to execute query: %v\n", err)
		}
		query := `INSERT INTO core_refreshtoken (token) VALUES ($1)`
		_, err = db.Exec(query, refreshToken)

		if err != nil {
			http.Error(w, "Error querying the database: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if !rows.Next() {
			http.Error(w, "Wrong username or password", http.StatusNotFound)
			return
		}

		var id, username, password, lastLogin, isSuperUser, firstName, lastName, email, isStaff, isActive, dateJoined, profile_id, birthdate, bio string

		err = rows.Scan(&id, &password, &lastLogin, &isSuperUser, &username, &firstName, &lastName, &email, &isStaff, &isActive, &dateJoined, &bio, &birthdate, &profile_id)
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
