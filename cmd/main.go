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
	"golang.org/x/crypto/bcrypt"
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
	w.Header().Set("Access-Control-Allow-Origin", "https://dearborncodingclub.com")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

func setBaseHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "https://dearborncodingclub.com")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func writeCORSHttpError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	w.Header().Set("Access-Control-Allow-Origin", "https://dearborncodingclub.com")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")
	http.Error(w, msg, code)
}

func main() {
	http.HandleFunc("/validate-token", func(w http.ResponseWriter, r *http.Request) {
		// During CORS preflight, the browser sends an OPTIONS request to check if the server allows the request.
		// Handle these responses early in function.
		if r.Method == http.MethodOptions {
			handlePreflight(w, r)
			return
		}

		// Parse the environment variables into a Config struct.
		var cfg Config
		err := env.Parse(&cfg)
		if err != nil {
			writeCORSHttpError(w, r, "Error parsing environment variables: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Retrieve the token from the Authorization header of the request.
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			writeCORSHttpError(w, r, "No token provided", http.StatusUnauthorized)
			return
		}

		// The token generally starts with "Authorization", so trim that part before processing.
		tokenString = tokenString[7:]

		// Parse the token and validate it is signed with the HMAC secret.
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte("potatosecret"), nil
		})
		if err != nil {
			writeCORSHttpError(w, r, "Error parsing JWT: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if !token.Valid {
			writeCORSHttpError(w, r, "Invalid token", http.StatusUnauthorized)
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			writeCORSHttpError(w, r, "Error parsing claims", http.StatusInternalServerError)
			return
		}

		// Set headers of the response.
		setBaseHeaders(w)

		fmt.Fprintf(w, `{"claims": %v}`, claims)
	})

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		// During CORS preflight, the browser sends an OPTIONS request to check if the server allows the request.
		// Handle these responses early in function.
		if r.Method == http.MethodOptions {
			handlePreflight(w, r)
			return
		}

		// Parse the environment variables into a Config struct.
		var cfg Config
		err := env.Parse(&cfg)
		if err != nil {
			writeCORSHttpError(w, r, "could build config"+err.Error(), http.StatusInternalServerError)
			return
		}

		// Parse the request body into a RegisterRequest struct.
		var registerRequest RegisterRequest
		err = json.NewDecoder(r.Body).Decode(&registerRequest)
		if err != nil {
			writeCORSHttpError(w, r, "Unable to decode response: "+err.Error(), http.StatusInternalServerError)
		}

		// Create a database connection string using the Supabase environment variables.
		connStr := fmt.Sprintf("postgresql://postgres.gxjlavvzckgdyjyuhgod:%s@aws-0-us-west-1.pooler.supabase.com:6543/postgres", cfg.Password)
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			writeCORSHttpError(w, r, "Error parsing request body: "+err.Error(), http.StatusNotFound)
			return
		}

		// Check if the user already exists in the database.
		rows, err := db.Query("SELECT * FROM ACCOUNTS_DCCUSER WHERE USERNAME = $1", registerRequest.Username)
		if err != nil {
			writeCORSHttpError(w, r, "Error selecting from database: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// If the user already exists, return an error.
		if rows.Next() {
			writeCORSHttpError(w, r, "User already exists", http.StatusConflict)
			return
		}

		hashedPassword, err := HashPassword(registerRequest.Password)

		if err != nil {
			writeCORSHttpError(w, r, "Error hashing password: "+err.Error(), http.StatusInternalServerError)
			return
		}
		var id int
		err = db.QueryRow("INSERT INTO ACCOUNTS_PROFILE (role, phone_number, email, address, about_me, leetcode_username) VALUES ('user', '', '', '', '', '') RETURNING id").Scan(&id)
		if err != nil {
			writeCORSHttpError(w, r, "Error inserting into profile: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err != nil {
			writeCORSHttpError(w, r, "Error getting last insert ID: "+err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO ACCOUNTS_DCCUSER (username, password, email, is_superuser, first_name, last_name, is_staff, is_active, date_joined, bio, birthdate, profile_id, last_login) VALUES ($1, $2, $3, FALSE, 'test_name', 'test_name', FALSE, FALSE, '2017-03-14', 'test-bio', '2017-03-14', $4, '2017-03-14')", registerRequest.Username, hashedPassword, registerRequest.Email, id)

		if err != nil {
			writeCORSHttpError(w, r, "Error querying the database: "+err.Error(), http.StatusInternalServerError)
			return
		}

		setBaseHeaders(w)
		fmt.Fprint(w, `{ "generated": true }`)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// During CORS preflight, the browser sends an OPTIONS request to check if the server allows the request.
		// Handle these responses early in function.
		if r.Method == http.MethodOptions {
			handlePreflight(w, r)
			return
		}

		// Parse the environment variables into a Config struct.
		var cfg Config
		err := env.Parse(&cfg)
		if err != nil {
			writeCORSHttpError(w, r, "Error parsing environment variables: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Generate a refresh token.
		refreshToken, err := GenerateRefreshToken()
		if err != nil {
			writeCORSHttpError(w, r, "Error generating refresh token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Parse the request body into a LoginRequest struct.
		var loginRequest LoginRequest
		err = json.NewDecoder(r.Body).Decode(&loginRequest)
		if err != nil {
			writeCORSHttpError(w, r, "Unable to decode response: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Create a database connection string using the Supabase environment variables.
		connStr := fmt.Sprintf("postgresql://postgres.gxjlavvzckgdyjyuhgod:%s@aws-0-us-west-1.pooler.supabase.com:6543/postgres", cfg.Password)
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			log.Fatalf("Unable to execute query: %v\n", err)
		}
		defer db.Close()

		// Query the database for the user.
		rows, err := db.Query("SELECT * FROM ACCOUNTS_DCCUSER WHERE username = $1", loginRequest.Username)
		if err != nil {
			log.Fatalf("Unable to execute query: %v\n", err)
		}

		// If the user does not exist, return an error.
		if !rows.Next() {
			writeCORSHttpError(w, r, "Wrong username or password", http.StatusNotFound)
			return
		}

		// Insert the refresh token into the database.
		query := `INSERT INTO core_refreshtoken (token) VALUES ($1)`
		_, err = db.Exec(query, refreshToken)
		if err != nil {
			writeCORSHttpError(w, r, "Error querying the database: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Parse the database response into a User struct.
		var id, username, password, lastLogin, isSuperUser, firstName, lastName, email, isStaff, isActive, dateJoined, profile_id, birthdate, bio string
		err = rows.Scan(&id, &password, &lastLogin, &isSuperUser, &username, &firstName, &lastName, &email, &isStaff, &isActive, &dateJoined, &bio, &birthdate, &profile_id)
		if err != nil {
			writeCORSHttpError(w, r, "Error scanning the database: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		// Check if the provided password hash matches what is in the database.
		validPassword := CheckPasswordHash(loginRequest.Password, password)
		if !validPassword {
			writeCORSHttpError(w, r, "Wrong password", http.StatusNotFound)
			return
		}

		// Insert the refresh token into the database.
		query = `INSERT INTO core_refreshtoken (token) VALUES ($1)`
		_, err = db.Exec(query, refreshToken)
		if err != nil {
			writeCORSHttpError(w, r, "Error querying the database: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Generate a JWT with the user claims.
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

		// Sign the JWT with the HMAC secret and convert it to a string.
		tokenString, err := token.SignedString([]byte("potatosecret"))
		if err != nil {
			writeCORSHttpError(w, r, "Error generating JWT: "+err.Error(), http.StatusInternalServerError)
			return
		}

		setBaseHeaders(w)

		fmt.Fprintf(w, `{"token": "%s", "refresh_token": "%s"}`, tokenString, refreshToken)
	})

	// Start the server listening on port 8080
	fmt.Println("Server running on port 8080")
	http.ListenAndServe(":8080", nil)
}

// Note: Bcrypt will not work on any passwords longer than 72 bytes (chars)
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
