package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"text/template"

	_ "github.com/mattn/go-sqlite3" // SQLite3 driver
	"golang.org/x/crypto/bcrypt"
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
	http.HandleFunc("/", HomePage)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/upload", uploadHandler)

	log.Println("Server starting on :8050...")
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
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == "POST" {
		action := r.FormValue("action")
		if action == "login" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		} else if action == "register" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	}
	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
	if r.Method != http.MethodPost {
		renderTemplate(w, map[string]interface{}{})
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if password != confirmPassword {
		renderTemplate(w, map[string]interface{}{
			"RegisterErrorMsg": "Passwords do not match",
			"Username":         username,
			"Email":            email,
		})
		return
	}
	re := regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$`)
	if !re.MatchString(email) {
		renderTemplate(w, map[string]interface{}{
			"RegisterErrorMsg": "Invalid email format",
			"Username":         username,
			"Email":            email,
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		renderTemplate(w, map[string]interface{}{
			"RegisterErrorMsg": fmt.Sprintf("Error hashing password: %v", err),
			"Username":         username,
			"Email":            email,
		})
		return
	}

	// SQL sorgusu burada düzeltilmiştir.
	_, err = db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", username, email, string(hashedPassword))
	if err != nil {
		renderTemplate(w, map[string]interface{}{
			"RegisterErrorMsg": fmt.Sprintf("Error registering user: %v", err),
			"Username":         username,
			"Email":            email,
		})
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func renderTemplate(w http.ResponseWriter, data map[string]interface{}) {
	t, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderTemplate(w, map[string]interface{}{
			"LoginErrorMsg": "Invalid request method",
		})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	var dbemail, dbPassword string
	err := db.QueryRow("SELECT email, password FROM users WHERE email = ?", email).Scan(&dbemail, &dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			renderTemplate(w, map[string]interface{}{
				"LoginErrorMsg": "User not found",
			})
			return
		}
		renderTemplate(w, map[string]interface{}{
			"LoginErrorMsg": fmt.Sprintf("Error querying user: %v", err),
		})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
	if err != nil {
		renderTemplate(w, map[string]interface{}{
			"LoginErrorMsg": "Invalid password",
		})
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	title := r.FormValue("title")

	// Dosyayı formdan çıkart
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Dizin yolu
	uploadDir := "./uploads"

	// Dizin yoksa oluştur
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		os.MkdirAll(uploadDir, os.ModePerm)
	}

	// Dosyayı diskte bir yere kaydet
	filePath := filepath.Join(uploadDir, handler.Filename)
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error saving file info to database: %v", err), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	io.Copy(f, file)

	// Dosya URL'sini ve title'ı veritabanına kaydet
	_, err = db.Exec("INSERT INTO posts (title, image_url) VALUES (?, ?)", title, "./"+filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error saving file info to database: %v", err), http.StatusInternalServerError)
		return
	}

	// Yükleme başarılı sayfası göster
	fmt.Fprintf(w, "File uploaded successfully: %+v", handler.Filename)
}
