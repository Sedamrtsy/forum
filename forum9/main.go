package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"text/template"

	_ "github.com/mattn/go-sqlite3" // SQLite3 driver
)

var db *sql.DB // Global database connection pointer

func main() {
	// Initialize the global database connection
	var err error
	db, err = sql.Open("sqlite3", "database/database.db")
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer db.Close() // Ensure the database connection is closed when main exits

	// Create database tables
	createTables()

	// Set up HTTP server
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))
	http.HandleFunc("/", HomePage)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/view_post", viewPostHandler)

	err = http.ListenAndServe(":8050", nil)
	if err != nil {
		log.Fatal("Error starting server: ", err)
	}
}

func HomePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// Çerezden kullanıcı giriş durumunu kontrol et
	loggedIn := false
	if cookie, err := r.Cookie("loggedin"); err == nil && cookie.Value == "true" {
		loggedIn = true
	}

	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Execute template with login status data
	data := struct {
		LoggedIn bool
	}{
		LoggedIn: loggedIn,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if r.Method == "POST" {
		action := r.FormValue("action")
		if action == "login" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		} else if action == "register" {
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}
	}
	// err = tmpl.Execute(w, nil)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// }
}

func createTables() {
	// SQL statement for creating a new table for users
	createUsersTable := `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        username TEXT UNIQUE,
        password TEXT
    );`
	_, err := db.Exec(createUsersTable)
	if err != nil {
		log.Fatalf("Error creating users table: %v", err)
	}

	// SQL statement for creating a new table for posts
	createPostsTable := `CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        content TEXT,
        author_id INTEGER,
		image_url TEXT UNIQUE,
		blok_url TEXT UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (author_id) REFERENCES users(id)
    );`
	_, err = db.Exec(createPostsTable)
	if err != nil {
		log.Fatalf("Error creating posts table: %v", err)
	}
	// SQL statement for creating a new table for comments
	createCommentsTable := `CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        content TEXT,
        author_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts(id),
        FOREIGN KEY (author_id) REFERENCES users(id)
    );`
	_, err = db.Exec(createCommentsTable)
	if err != nil {
		log.Fatalf("Error creating comments table: %v", err)
	}

	// SQL statement for creating a new table for likes
	createLikesTable := `CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        post_id INTEGER,
        comment_id INTEGER,
        like BOOLEAN,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (post_id) REFERENCES posts(id),
        FOREIGN KEY (comment_id) REFERENCES comments(id)
    );`
	_, err = db.Exec(createLikesTable)
	if err != nil {
		log.Fatalf("Error creating likes table: %v", err)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	_, err := db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", username, email, password)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error registering user: %v", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	var dbEmail, dbPassword string
	err := db.QueryRow("SELECT email, password FROM users WHERE email = ?", email).Scan(&dbEmail, &dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}
		http.Error(w, fmt.Sprintf("Error querying user: %v", err), http.StatusInternalServerError)
		return
	}

	if password != dbPassword {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}
	// Set a cookie indicating the user is logged in
	http.SetCookie(w, &http.Cookie{
		Name:   "loggedin",
		Value:  "true",
		Path:   "/",
		MaxAge: 120, // 120 sn boyunca kulanıcı hiç bir şey yapmazsa oturum kapanır, cookies silinir
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Log out by setting the cookie to expire immediately
	http.SetCookie(w, &http.Cookie{
		Name:   "loggedin",
		Value:  "",
		Path:   "/",
		MaxAge: -1, // Immediately expire the cookie
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, err := template.ParseFiles("templates/uploadForm.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	title := r.FormValue("title")

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	uploadDir := "./uploads"

	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		os.MkdirAll(uploadDir, os.ModePerm)
	}

	filePath := filepath.Join(uploadDir, handler.Filename)
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error saving file info to database: %v", err), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	io.Copy(f, file)

	_, err = db.Exec("INSERT INTO posts (title, image_url) VALUES (?, ?)", title, "./"+filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error saving file info to database: %v", err), http.StatusInternalServerError)
		return
	}

	//http.Redirect(w, r, "/", http.StatusSeeOther)

	http.Redirect(w, r, fmt.Sprintf("/view_post?title=%s&image=%s", title, handler.Filename), http.StatusSeeOther)
}
func viewPostHandler(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Query().Get("title")
	image := r.URL.Query().Get("image")

	data := map[string]interface{}{
		"Title": title,
		"Image": "/uploads/" + image,
	}

	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
