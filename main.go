package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var db *gorm.DB
var sessionSecret = []byte("your-secret-key")
var store = cookie.NewStore(sessionSecret)

type Library struct {
	ID   uint   `gorm:"primary_key"`
	Name string `gorm:"unique"`
}

type IssueRegistry struct {
	IssueID            uint `gorm:"primary_key"`
	ISBN               string
	ReaderID           string
	IssueApproverID    *uint
	IssueStatus        string
	IssueDate          time.Time
	ExpectedReturnDate time.Time
	ReturnDate         *time.Time
	ReturnApproverID   *uint
}

type User struct {
	ID            uint `gorm:"primary_key"`
	Name          string
	Email         string `gorm:"unique;not null"`
	Password      string `gorm:"not null"`
	Role          string `gorm:"not null"`
	ContactNumber string
	LibID         uint
}

type BookInventory struct {
	ID              uint `gorm:"primary_key"`
	LibID           uint
	ISBN            string `gorm:"unique"`
	Title           string
	Authors         string
	Publisher       string
	Version         string
	TotalCopies     uint
	AvailableCopies uint
}

type RequestEvents struct {
	ReqID        uint `gorm:"primary_key"`
	BookID       uint
	ReaderID     string
	RequestDate  time.Time
	ApprovalDate *time.Time
	ApproverID   *uint
	RequestType  string
}

func createLibrary(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var existingLibrary Library
	if err := db.Where("name = ?", req.Name).First(&existingLibrary).Error; err == nil {
		c.JSON(400, gin.H{"error": "Library with the same name already exists"})
		return
	}

	newLibrary := Library{Name: req.Name}
	if err := db.Create(&newLibrary).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to create library"})
		return
	}

	newUser := User{Name: "Owner", Role: "Owner", LibID: newLibrary.ID}
	if err := db.Create(&newUser).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to add owner to the library"})
		return
	}

	c.JSON(200, newLibrary)
}

func registerUser(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	role := c.PostForm("role")

	if email == "" || password == "" || role == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email, password, and role are required"})
		return
	}

	// Check if the email is already registered
	var existingUser User
	if err := db.Where("email = ?", email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already registered"})
		return
	}

	// Create new user
	newUser := User{
		Email:    email,
		Password: password,
		Role:     role,
	}
	if err := db.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

func searchBook(c *gin.Context) {
	var req struct {
		Title     string `json:"title"`
		Author    string `json:"author"`
		Publisher string `json:"publisher"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var books []BookInventory
	query := db.Model(&BookInventory{})
	if req.Title != "" {
		query = query.Where("title LIKE ?", "%"+req.Title+"%")
	}
	if req.Author != "" {
		query = query.Where("authors LIKE ?", "%"+req.Author+"%")
	}
	if req.Publisher != "" {
		query = query.Where("publisher LIKE ?", "%"+req.Publisher+"%")
	}
	query.Find(&books)

	c.JSON(200, books)
}

func raiseIssueRequest(c *gin.Context) {
	var req struct {
		BookID uint   `json:"book_id" binding:"required"`
		Email  string `json:"email" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var book BookInventory
	if err := db.Where("id = ? AND available_copies > 0", req.BookID).First(&book).Error; err != nil {
		c.JSON(400, gin.H{"error": "Book is not available"})
		return
	}

	newRequest := RequestEvents{
		BookID:      req.BookID,
		ReaderID:    req.Email,
		RequestDate: time.Now(),
		RequestType: "Issue",
	}
	if err := db.Create(&newRequest).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to raise issue request"})
		return
	}

	c.JSON(200, gin.H{"message": "Issue request raised successfully"})
}

// Function to add books to the inventory
func addBook(c *gin.Context) {
	var req struct {
		LibID           uint   `json:"library_id" binding:"required"`
		ISBN            string `json:"isbn" binding:"required"`
		Title           string `json:"title" binding:"required"`
		Authors         string `json:"authors" binding:"required"`
		Publisher       string `json:"publisher" binding:"required"`
		Version         string `json:"version" binding:"required"`
		TotalCopies     uint   `json:"total_copies" binding:"required"`
		AvailableCopies uint   `json:"available_copies" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var existingBook BookInventory
	if err := db.Where("isbn = ?", req.ISBN).First(&existingBook).Error; err == nil {
		// If the book already exists, update the number of copies
		existingBook.TotalCopies += req.TotalCopies
		existingBook.AvailableCopies += req.AvailableCopies
		if err := db.Save(&existingBook).Error; err != nil {
			c.JSON(500, gin.H{"error": "Failed to update book"})
			return
		}
		c.JSON(200, existingBook)
		return
	}

	// Create a new book entry
	newBook := BookInventory{
		LibID:           req.LibID,
		ISBN:            req.ISBN,
		Title:           req.Title,
		Authors:         req.Authors,
		Publisher:       req.Publisher,
		Version:         req.Version,
		TotalCopies:     req.TotalCopies,
		AvailableCopies: req.AvailableCopies,
	}
	if err := db.Create(&newBook).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to add book"})
		return
	}

	c.JSON(200, newBook)
}

// Function to remove a book from the inventory
func removeBook(c *gin.Context) {
	var req struct {
		BookID uint `json:"book_id" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var book BookInventory
	if err := db.First(&book, req.BookID).Error; err != nil {
		c.JSON(404, gin.H{"error": "Book not found"})
		return
	}

	if book.TotalCopies <= 0 {
		c.JSON(400, gin.H{"error": "No copies of this book available"})
		return
	}

	// Check if any copies are issued
	var issuedCopies uint
	if err := db.Model(&RequestEvents{}).Where("book_id = ? AND request_type = ?", req.BookID, "Issue").Count(&issuedCopies).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to check issued copies"})
		return
	}

	if issuedCopies > 0 {
		c.JSON(400, gin.H{"error": "Some copies of this book are issued and cannot be removed"})
		return
	}

	// Decrement the number of copies
	book.TotalCopies--
	book.AvailableCopies--
	if err := db.Save(&book).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to remove book"})
		return
	}

	c.JSON(200, gin.H{"message": "Book removed successfully"})
}

// Function to update book details using ISBN
func updateBook(c *gin.Context) {
	var req struct {
		ISBN      string `json:"isbn" binding:"required"`
		Title     string `json:"title" binding:"required"`
		Authors   string `json:"authors" binding:"required"`
		Publisher string `json:"publisher" binding:"required"`
		Version   string `json:"version" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var book BookInventory
	if err := db.Where("isbn = ?", req.ISBN).First(&book).Error; err != nil {
		c.JSON(404, gin.H{"error": "Book not found"})
		return
	}

	// Update book details
	book.Title = req.Title
	book.Authors = req.Authors
	book.Publisher = req.Publisher
	book.Version = req.Version

	if err := db.Save(&book).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to update book"})
		return
	}

	c.JSON(200, book)
}

// Function to list all issue requests in the library
func listIssueRequests(c *gin.Context) {
	var requests []RequestEvents
	if err := db.Find(&requests).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch issue requests"})
		return
	}

	c.JSON(200, requests)
}

// Function to approve or reject issue requests
func approveOrRejectIssueRequest(c *gin.Context) {
	var req struct {
		ReqID        uint   `json:"request_id" binding:"required"`
		Approved     bool   `json:"approved"`
		ApproverID   uint   `json:"approver_id" binding:"required"`
		ApprovalDate string `json:"approval_date" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var request RequestEvents
	if err := db.First(&request, req.ReqID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Request not found"})
		return
	}

	var book BookInventory
	if err := db.First(&book, request.BookID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Book not found"})
		return
	}

	if req.Approved {
		// Set request details if approved
		request.ApproverID = &req.ApproverID
		approvalDate, err := time.Parse(time.RFC3339, req.ApprovalDate)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid approval date format"})
			return
		}
		request.ApprovalDate = &approvalDate

		// Update request event with approval details
		if err := db.Save(&request).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update request"})
			return
		}

		// Update issue registry accordingly
		newIssue := IssueRegistry{
			ISBN:               book.ISBN,
			ReaderID:           request.ReaderID,
			IssueApproverID:    &req.ApproverID,
			IssueStatus:        "Approved",
			IssueDate:          time.Now(),
			ExpectedReturnDate: time.Now().AddDate(0, 0, 7), // Example: Expected return date after 7 days
		}
		if err := db.Create(&newIssue).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update issue registry"})
			return
		}

		// Decrease available copies of the book by 1
		book.AvailableCopies--
		if err := db.Save(&book).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update book inventory"})
			return
		}
	} else {
		// If rejected, delete the request
		if err := db.Delete(&request).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete request"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Issue request updated successfully"})
}

func isAuthenticated(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		sessionRole := session.Get("role")
		sessionEmail := session.Get("email")

		// Check if the session role is set and matches the expected role
		if sessionRole != nil && strings.EqualFold(sessionRole.(string), role) {
			c.Next()
			return
		}

		// Check if the session email is set and retrieve the user role from the database
		if sessionEmail != nil {
			var user User
			err := db.Where("email = ?", sessionEmail).First(&user).Error
			if err != nil {
				// Handle database query error
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information"})
				c.Abort()
				return
			}

			if strings.EqualFold(user.Role, role) {
				// Update the session with the user's role
				session.Set("role", user.Role)
				err = session.Save()
				if err != nil {
					// Handle session save error
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
					c.Abort()
					return
				}

				c.Next()
				return
			}
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
		c.Abort()
	}
}

func authenticate(email, password string) bool {
	var user User
	if err := db.Where("email = ? AND password = ?", email, password).First(&user).Error; err != nil {
		return false
	}
	return true
}

func loginUser(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	if !authenticate(req.Email, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	session := sessions.Default(c)
	session.Set("email", req.Email)
	err := session.Save()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "email": req.Email})
}

func main() {
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	r.Use(sessions.Sessions("session", store))

	var err error
	db, err = gorm.Open("sqlite3", "library.db")
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	db.AutoMigrate(&Library{}, &User{}, &BookInventory{}, &RequestEvents{}, &IssueRegistry{})

	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})

	r.POST("/login", loginUser)

	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", nil)
	})

	r.POST("/register", registerUser)

	adminRoutes := r.Group("/admin", isAuthenticated("Admin"))
	{
		adminRoutes.POST("/books", addBook)
		adminRoutes.DELETE("/books/:isbn", removeBook)
		adminRoutes.PUT("/books/:isbn", updateBook)
		adminRoutes.GET("/issue-requests", listIssueRequests)
		adminRoutes.PUT("/issue-requests/:id", approveOrRejectIssueRequest)
	}

	ownerRoutes := r.Group("/owner", isAuthenticated("Owner"))
	{
		ownerRoutes.POST("/libraries", createLibrary)
	}

	readerRoutes := r.Group("/reader", isAuthenticated("Reader"))
	{
		readerRoutes.POST("/search", searchBook)
		readerRoutes.POST("/issue-requests", raiseIssueRequest)
	}

	r.Run(":8080")
}
