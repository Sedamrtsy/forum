package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"text/template"


	_ "github.com/mattn/go-sqlite3" // SQLite3 driver
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB // Global database connection pointer
type Post struct {
	Title      string
	ImageURL   string
	AuthorName string
}

func main() {
	initDatabase()   // Initialize the global database connection
	defer db.Close() // Ensure the database connection is closed when main exits
	createTables()   // Create database tables
	setupRoutes()    // Set up HTTP server

	err := http.ListenAndServe(":8040", nil)
	if err != nil {
		log.Fatal("Error starting server: ", err)
	}
}

func initDatabase() {
	var err error
	db, err = sql.Open("sqlite3", "database/database.db")
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
}

func createTables() {
	// SQL statement for creating a new table for users
	createUsersTable := `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        username TEXT UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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

func setupRoutes() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))
	http.HandleFunc("/", HomePage)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/view_post", viewPostHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/edit", editHandler)
}

func HomePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	loggedIn := checkLoginStatus(r)

	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rows, err := db.Query("SELECT p.title, p.image_url, u.username FROM posts p JOIN users u ON p.author_id = u.id ORDER BY p.created_at DESC")
	if err != nil {
		log.Printf("Error fetching posts: %v", err)
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.Title, &post.ImageURL, &post.AuthorName); err != nil {
			log.Printf("Error scanning post: %v", err)
			http.Error(w, "Error scanning post", http.StatusInternalServerError)
			return
		}
		posts = append(posts, post)
	}

	data := struct {
		LoggedIn bool
		Posts    []Post
	}{
		LoggedIn: loggedIn,
		Posts:    posts,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

func checkLoginStatus(r *http.Request) bool {
	cookie, err := r.Cookie("loggedin")
	if err == nil && cookie.Value == "true" {
		return true
	}
	return false
}

func setLoginCookie(w http.ResponseWriter, userID int, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:   "loggedin",
		Value:  value,
		Path:   "/",
		MaxAge: maxAge,
	})
	//////
	http.SetCookie(w, &http.Cookie{
		Name:   "userid",
		Value:  fmt.Sprintf("%d", userID),
		Path:   "/",
		MaxAge: maxAge,
	})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTemplate(w, "templates/login.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		renderTemplate(w, "templates/login.html", map[string]interface{}{
			"RegisterErrorMsg": fmt.Sprintf("Error hashing password: %v", err),
			"Username":         username,
			"Email":            email,
		})
		return
	}
	_, err = db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", username, email, string(hashedPassword))
	if err != nil {
		renderTemplate(w, "templates/login.html", map[string]interface{}{
			"RegisterErrorMsg": fmt.Sprintf("Error registering user: %v", err),
			"Username":         username,
			"Email":            email,
		})
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTemplate(w, "templates/login.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		renderTemplate(w, "templates/login.html", map[string]interface{}{
			"LoginErrorMsg": "Invalid request method",
		})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	var dbEmail, dbPassword string
	var userID int
	err := db.QueryRow("SELECT id, email, password FROM users WHERE email = ?", email).Scan(&userID, &dbEmail, &dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			renderTemplate(w, "templates/login.html", map[string]interface{}{
				"LoginErrorMsg": "User not found",
			})
			return
		}
		renderTemplate(w, "templates/login.html", map[string]interface{}{
			"LoginErrorMsg": fmt.Sprintf("Error querying user: %v", err),
		})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
	if err != nil {
		renderTemplate(w, "templates/login.html", map[string]interface{}{
			"LoginErrorMsg": "Invalid password",
		})
		return
	}
	// userid, err := getUserIDFromCookie(r)
	// if err != nil {
	// 	log.Println(err)
	// }
	setLoginCookie(w, userID, "true", 720) // 120 seconds session duration
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	userid, err := getUserIDFromCookie(r)
	if err != nil {
		log.Println(err)
	}
	setLoginCookie(w, userid, "", -1) // Immediately expire the cookie
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTemplate(w, "templates/uploadForm.html", nil)
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
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0o666)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error saving file info to database: %v", err), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	io.Copy(f, file)

	// _, err = db.Exec("INSERT INTO posts (title, image_url) VALUES (?, ?)", title, "/"+filePath)
	// if err != nil {
	// 	http.Error(w, fmt.Sprintf("Error saving file info to database: %v", err), http.StatusInternalServerError)
	// 	return
	// }
	// Kullanıcı ID'sini çerezden al
	userID, err := getUserIDFromCookie(r)
	fmt.Println(userID)
	if err != nil {
		http.Error(w, "Not logged in", http.StatusForbidden)
		return
	}

	_, err = db.Exec("INSERT INTO posts (title, image_url, author_id) VALUES (?, ?, ?)", title, "/"+filePath, userID)
	// Error handling vs.
	if err != nil {
		log.Println(err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getUserIDFromCookie(r *http.Request) (int, error) {
	cookie, err := r.Cookie("userid")
	if err != nil {
		fmt.Println(err)
		return 0, err
	}
	userID, err := strconv.Atoi(cookie.Value)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

func viewPostHandler(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Query().Get("title")
	image := r.URL.Query().Get("image")

	data := map[string]interface{}{
		"Title": title,
		"Image": "/uploads/" + image,
	}

	renderTemplate(w, "templates/view_post.html", data)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	if !checkLoginStatus(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	userID, err := getUserIDFromCookie(r)
	if err != nil {
		http.Error(w, "Not logged in", http.StatusForbidden)
		return
	}

	// Fetch the user's posts from the database
	rows, err := db.Query("SELECT p.title, p.image_url, u.username FROM posts p JOIN users u ON p.author_id = u.id WHERE p.author_id = ? ORDER BY p.created_at DESC", userID)
	if err != nil {
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var username, email string
	err = db.QueryRow("SELECT username, email FROM users WHERE id = ?", userID).Scan(&username, &email)
	if err != nil {
		http.Error(w, "Error fetching user profile", http.StatusInternalServerError)
		return
	}

	var posts []Post
	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.Title, &post.ImageURL, &post.AuthorName); err != nil {
			http.Error(w, "Error scanning post", http.StatusInternalServerError)
			return
		}
		posts = append(posts, post)
	}

	data := struct {
		LoggedIn bool
		Posts    []Post
		Username string
		Email    string
	}{
		LoggedIn: true,
		Posts:    posts,
		Username: username,
		Email:    email,
	}

	renderTemplate(w, "templates/profile.html", data)
}

func renderTemplate(w http.ResponseWriter, templateFile string, data interface{}) {
	tmpl, err := template.ParseFiles(templateFile)
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

func editHandler(w http.ResponseWriter, r *http.Request) {
	// tmpl, err := template.ParseFiles("templates/edit.html")
	// if err != nil {
	// 	log.Printf("Error loading edit template: %v", err)
	// 	http.Error(w, "Error loading page", http.StatusInternalServerError)
	// 	return
	// }
	var username, email string
	//var createdAt time.Time
	userID, err := getUserIDFromCookie(r)
	if err != nil {
		http.Error(w, "Not logged in", http.StatusForbidden)
		return
	}
	//err = db.QueryRow("SELECT username, email, created_at FROM users WHERE id = ?", userID).Scan(&username, &email, &createdAt)
	err = db.QueryRow("SELECT username, email FROM users WHERE id = ?", userID).Scan(&username, &email)

	if err != nil {
		http.Error(w, "Error fetching user profile", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username  string
		Email     string
		//CreatedAt time.Time // time.Time türünde bir CreatedAt alanı ekleyin
	}{
		Username:  username,
		Email:     email,
		//CreatedAt: createdAt, // Veriyi saklayın
	}

	renderTemplate(w, "templates/edit.html", data)
	// err = tmpl.Execute(w, nil)
	// if err != nil {
	// 	log.Printf("Error executing edit template: %v", err)
	// 	http.Error(w, "Error rendering page", http.StatusInternalServerError)
	// }
}
