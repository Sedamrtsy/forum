package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"forum/utils"
)

var (
	oauthConf = &oauth2.Config{
		ClientID:     "330232552740-fr5h4k24b5h8dlpk79phlitrjpa5873k.apps.googleusercontent.com",
		ClientSecret: "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",
		RedirectURL:  "http://localhost:8040/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
	oauthStateString = "random"
)

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	oauthStateString = generateNonce()
	url := oauthConf.AuthCodeURL(oauthStateString, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != oauthStateString {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	token, err := oauthConf.Exchange(context.Background(), code)
	if err != nil {
		fmt.Printf("oauthConf.Exchange() failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	resp, err := http.Get(fmt.Sprintf("https://www.googleapis.com/oauth2/v2/userinfo?access_token=%s", token.AccessToken))
	if err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var userID int
	err = utils.Db.QueryRow("SELECT id FROM users WHERE email = ?", googleUser.Email).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			_, err = utils.Db.Exec("INSERT INTO users (username, email, usericon_url) VALUES (?, ?, ?)", googleUser.Name, googleUser.Email, googleUser.Picture)
			if err != nil {
				fmt.Printf("Error registering user: %v", err)
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}
			err = utils.Db.QueryRow("SELECT id FROM users WHERE email = ?", googleUser.Email).Scan(&userID)
			if err != nil {
				fmt.Printf("Error fetching new user ID: %v", err)
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}
		} else {
			fmt.Printf("Error querying user: %v", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
	}

	sessionToken := utils.GenerateSessionToken()
	expiration := time.Now().Add(24 * time.Hour)

	_, err = utils.Db.Exec("UPDATE users SET session_token = ?, token_expires = ? WHERE id = ?", sessionToken, expiration, userID)
	if err != nil {
		http.Error(w, "Failed to update session token.", http.StatusInternalServerError)
		return
	}

	utils.SetLoginCookie(w, userID, sessionToken, int(time.Until(expiration).Seconds()))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func generateNonce() string {
	b := make([]byte, 16) // 128-bit
	_, err := rand.Read(b)
	if err != nil {
		fmt.Printf("Failed to generate nonce: %v", err)
	}
	return hex.EncodeToString(b)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")

	if r.Method == http.MethodGet {
		utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
			"Redirect": redirect,
		})
		return
	}

	if r.Method != http.MethodPost {
		utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
			"LoginErrorMsg": "Invalid request method",
		})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" && password == "" {
		handleGoogleLogin(w, r)
		return
	}

	var dbEmail, dbPassword string
	var userID int
	err := utils.Db.QueryRow("SELECT id, email, password FROM users WHERE email = ?", email).Scan(&userID, &dbEmail, &dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
				"LoginErrorMsg": "User not found",
				"Redirect":      redirect,
			})
			return
		}
		utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
			"LoginErrorMsg": fmt.Sprintf("Error querying user: %v", err),
			"Redirect":      redirect,
		})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
	if err != nil {
		utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
			"LoginErrorMsg": "Invalid email or password",
			"Redirect":      redirect,
		})
		return
	}

	sessionToken := utils.GenerateSessionToken()
	expiration := time.Now().Add(24 * time.Hour)

	_, err = utils.Db.Exec("UPDATE users SET session_token = ?, token_expires = ? WHERE id = ?", sessionToken, expiration, userID)
	if err != nil {
		http.Error(w, "Failed to update session token.", http.StatusInternalServerError)
		return
	}

	utils.SetLoginCookie(w, userID, sessionToken, int(time.Until(expiration).Seconds()))

	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		utils.RenderTemplate(w, "templates/register.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirmPassword")

	if password != confirmPassword {
		utils.RenderTemplate(w, "templates/register.html", map[string]interface{}{
			"RegisterErrorMsg": "Passwords do not match",
			"Username":         username,
			"Email":            email,
		})
		return
	}

	emailRegex := `^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`
	matched, err := regexp.MatchString(emailRegex, email)
	if err != nil || !matched {
		utils.RenderTemplate(w, "templates/register.html", map[string]interface{}{
			"RegisterErrorMsg": "Invalid email format",
			"Username":         username,
			"Email":            email,
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		utils.RenderTemplate(w, "templates/register.html", map[string]interface{}{
			"RegisterErrorMsg": fmt.Sprintf("Error hashing password: %v", err),
			"Username":         username,
			"Email":            email,
		})
		return
	}

	_, err = utils.Db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", username, email, string(hashedPassword))
	if err != nil {
		utils.RenderTemplate(w, "templates/register.html", map[string]interface{}{
			"RegisterErrorMsg": fmt.Sprintf("Error registering user: %v", err),
			"Username":         username,
			"Email":            email,
		})
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	userid, err := utils.GetUserIDFromCookie(r)
	if err != nil {
		log.Println(err)
	}
	utils.SetLoginCookie(w, userid, "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
