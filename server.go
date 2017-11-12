package main

import (
	"log"
	"path"
	"strconv"

	"github.com/davecgh/go-spew/spew"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

var store *sessions.CookieStore

func GetRouter(db *ITrackDatabase) *gin.Engine {
	log.Print("initializing server for host " + db.Hostname)
	// Creates a router without any middleware by default
	r := gin.New()

	// Logging and default errors
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Static("/static", Config.ThemeDir)

	// Sessions
	store := sessions.NewCookieStore([]byte(Config.SessionKey))
	r.Use(sessions.Sessions("lnb-session", store))

	// Api set-up and routes
	api := r.Group("/api")
	api.Use(func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		c.Next()
	})

	api.POST("/login", login)
	api.GET("/tracks", getTracks(db))
	api.GET("/users", getUsers)

	authorized := api.Group("/")
	authorized.Use(auth)
	{
		authorized.POST("/logout", logout)

		authorized.POST("/tracks", addTrack(db))
		authorized.POST("/tracks/:trackId", updateTrack(db))
		authorized.POST("/tracks/:trackId/publish", publishTrack(db))
		authorized.DELETE("/tracks/:trackId", deleteTrack(db))

		authorized.POST("/users", addUser)
		authorized.POST("/users/:userId", updateUser)
		authorized.POST("/users/:userId/password", updateUserPassword)
	}

	r.NoRoute(func(c *gin.Context) {
		c.File(path.Join(Config.ThemeDir, "index.html"))
	})

	return r
}

// Utility
type errorResponse struct {
	Error string `json: "error"`
}

func auth(c *gin.Context) {
	session := sessions.Default(c)
	userId := session.Get("userId")

	if userId == nil {
		c.Status(403)
		c.Abort()
	} else {
		c.Next()
	}
}

// General

type userRequest struct {
	Name     string   `json: "name"`
	Password string   `json: "password"`
	Role     string   `json: "role"`
	Hosts    []string `json: "hosts"`
}

type userResponse struct {
	ID   string `json: "id"`
	Name string `json: "name"`
}

type authenticatedUserResponse struct {
	ID    string   `json: "id"`
	Name  string   `json: "name"`
	Role  string   `json: "role"`
	Hosts []string `json: "hosts"`
}

func login(c *gin.Context) {
	session := sessions.Default(c)
	userIdI := session.Get("userId")
	userNameI := session.Get("userName")
	userRoleI := session.Get("userRole")
	userHostsI := session.Get("userHosts")

	if userIdI != nil {
		userID, ok := userIdI.(string)
		userName := userNameI.(string)
		userRole := userRoleI.(string)
		userHosts := userHostsI.([]string)

		if ok && len(userID) > 0 {
			c.JSON(200, authenticatedUserResponse{userID, userName, userRole, userHosts})
			return
		}
	}

	var requestData userRequest
	c.BindJSON(&requestData)

	user := UserDatabase.getUserByName(requestData.Name)
	if user != nil {
		if !user.inHost(c.Request.Host) {
			c.JSON(403, errorResponse{"Invalid login data"})
		}

		err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(requestData.Password))
		if err == nil {
			session.Set("userName", user.Name)
			session.Set("userId", user.ID)
			session.Set("userRole", user.Role)
			session.Set("userHosts", user.Hosts)
			session.Set("userPassword", user.Password)
			session.Save()
			c.JSON(200, authenticatedUserResponse{user.ID, user.Name, user.Role, user.Hosts})
			return
		}
	}

	c.JSON(403, errorResponse{"Invalid login data"})
}

func logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.JSON(200, struct{}{})
}

// Tracks

func getTracks(db *ITrackDatabase) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userId := session.Get("userId")

		if userId != nil {
			c.JSON(200, db.Tracks)
		} else {
			c.JSON(200, db.getPublishedTracks())
		}
	}
}

type trackRequest struct {
	Artist  string `json: "artist"`
	Title   string `json: "title"`
	Release string `json: "release"`
	Url     string `json: "url"`
}

func addTrack(db *ITrackDatabase) gin.HandlerFunc {
	return func(c *gin.Context) {
		var requestData trackRequest
		c.BindJSON(&requestData)
		session := sessions.Default(c)
		userId := session.Get("userId")

		id := userId.(string)

		if len(requestData.Artist) == 0 {
			c.JSON(400, errorResponse{"Invalid artist"})
		}

		if len(requestData.Title) == 0 {
			c.JSON(400, errorResponse{"Invalid title"})
		}

		if len(requestData.Release) == 0 {
			c.JSON(400, errorResponse{"Invalid release"})
		}

		if len(requestData.Url) == 0 {
			c.JSON(400, errorResponse{"Invalid url"})
		}

		track := ITrack{
			ID:       uuid.NewV4().String(),
			Episode:  nil,
			Artist:   requestData.Artist,
			Title:    requestData.Title,
			Release:  requestData.Release,
			Url:      requestData.Url,
			Uploader: id,
		}
		db.addTrack(track)

		c.JSON(200, track)
	}
}

func updateTrack(db *ITrackDatabase) gin.HandlerFunc {
	return func(c *gin.Context) {
		var requestData trackRequest
		c.BindJSON(&requestData)
		trackId := c.Param("trackId")

		log.Println(trackId)

		if len(requestData.Artist) == 0 {
			c.JSON(400, errorResponse{"Invalid artist"})
		}

		if len(requestData.Title) == 0 {
			c.JSON(400, errorResponse{"Invalid title"})
		}

		if len(requestData.Release) == 0 {
			c.JSON(400, errorResponse{"Invalid release"})
		}

		if len(requestData.Url) == 0 {
			c.JSON(400, errorResponse{"Invalid url"})
		}

		track := db.getTrackById(trackId)

		if track != nil {
			track.Artist = requestData.Artist
			track.Title = requestData.Title
			track.Release = requestData.Release
			track.Url = requestData.Url
			db.write()

			c.JSON(200, *track)
		} else {
			c.JSON(404, errorResponse{"Track not found"})
			c.Abort()
		}
	}
}

func publishTrack(db *ITrackDatabase) gin.HandlerFunc {
	return func(c *gin.Context) {
		trackId := c.Param("trackId")
		track := db.getTrackById(trackId)

		if track != nil {
			if track.Episode != nil {
				c.JSON(400, errorResponse{"Track already published at episode " + strconv.FormatInt(int64(*track.Episode), 10)})
				return
			}

			latestEpisode := db.getNewEpisodeNumber()
			log.Println(latestEpisode)
			track.Episode = &latestEpisode
			log.Println(track.Episode, *track.Episode)
			spew.Dump(track)
			spew.Dump(db.Tracks)
			db.write()
			c.JSON(200, track)
		} else {
			c.JSON(404, errorResponse{"Track not found"})
		}
	}
}

func deleteTrack(db *ITrackDatabase) gin.HandlerFunc {
	return func(c *gin.Context) {
		trackId := c.Param("trackId")
		track := db.getTrackById(trackId)

		if track == nil {
			c.JSON(404, errorResponse{"Track not found"})
		} else if track.Episode != nil {
			c.JSON(403, errorResponse{"Track already published"})
		} else {
			deletedTrack := db.deleteTrack(trackId)
			c.JSON(200, *deletedTrack)
		}
	}
}

// Users

func getUsers(c *gin.Context) {
	session := sessions.Default(c)
	userRole := session.Get("userRole")

	if userRole == "admin" {
		c.JSON(200, UserDatabase.Users)
	} else {
		response := make([]userResponse, 0)
		for _, user := range UserDatabase.Users {
			if user.inHost(c.Request.Host) {
				response = append(response, userResponse{user.ID, user.Name})
			}
		}
		c.JSON(200, response)
	}
}

func addUser(c *gin.Context) {
	session := sessions.Default(c)
	userRole := session.Get("userRole")

	if userRole != "admin" {
		c.JSON(403, errorResponse{"Insufficient rights"})
	}

	var requestData userRequest
	c.BindJSON(&requestData)

	if len(requestData.Name) == 0 {
		c.JSON(400, errorResponse{"Invalid name"})
	}

	if len(requestData.Password) < 12 {
		c.JSON(400, errorResponse{"Invalid Password. Minimum length is 12"})
	}

	if len(requestData.Role) == 0 || (requestData.Role != "submitter" && requestData.Role != "admin") {
		c.JSON(400, errorResponse{"Invalid Role. Provide either 'admin' or 'submitter'"})
	}

	if len(requestData.Hosts) == 0 {
		requestData.Hosts = append(requestData.Hosts, c.Request.Host)
	}

	user := UserDatabase.getUserByName(requestData.Name)

	if len(user.Name) > 0 {
		c.JSON(400, errorResponse{"User already exists"})
		return
	}

	password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, errorResponse{"Something went wrong"})
	}

	id := uuid.NewV4()
	newUser := IUser{
		id.String(),
		requestData.Name,
		string(password),
		requestData.Role,
		requestData.Hosts,
	}
	UserDatabase.addUser(newUser)

	c.JSON(200, userResponse{newUser.ID, newUser.Name})
}

func updateUser(c *gin.Context) {
	var requestData userRequest
	c.BindJSON(&requestData)
	userId := c.Param("userId")

	if len(requestData.Name) == 0 {
		c.JSON(400, errorResponse{"Invalid name"})
	}

	if len(requestData.Password) < 12 {
		c.JSON(400, errorResponse{"Invalid Password. Minimum length is 12"})
	}

	user := UserDatabase.getUserById(userId)

	if len(user.Name) > 0 {
		password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(500, errorResponse{"Something went wrong"})
		}

		user.Name = requestData.Name
		user.Password = string(password)
		UserDatabase.write()
	} else {
		c.JSON(404, errorResponse{"User not found"})
	}
}

type passwordUpdateRequest struct {
	CurrentUserPassword string `json: "currentUserPassword"`
	Password            string `json: "password"`
	PasswordRepeat      string `json: "passwordRepeat"`
}

func updateUserPassword(c *gin.Context) {
	session := sessions.Default(c)
	userRole := session.Get("userRole").(string)
	userId := session.Get("userId").(string)
	currUserPassword := session.Get("userPassword").([]byte)
	userToUpdateId := c.Param("userId")
	var requestData passwordUpdateRequest
	c.BindJSON(&requestData)

	err := bcrypt.CompareHashAndPassword(currUserPassword, []byte(requestData.CurrentUserPassword))
	if err != nil {
		c.JSON(403, errorResponse{"Incorrect current password"})
	}

	if userRole == "admin" || userId == userToUpdateId {
		if requestData.Password != requestData.PasswordRepeat {
			c.JSON(400, errorResponse{"Passwords do not match"})
		}

		password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(500, errorResponse{"Something went wrong"})
			return
		}

		user := UserDatabase.getUserById(userId)
		user.Password = string(password)
		UserDatabase.write()

	} else {
		c.JSON(403, errorResponse{"Insufficient rights"})
	}
}
