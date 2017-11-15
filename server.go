package main

import (
	"log"
	"path"
	"strconv"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

// The cookie store
var store *sessions.CookieStore

// The router initializing function.
// Takes the track database associated with the host as only argument
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

	// Unauthenticated API routes
	api.POST("/login", login)
	api.GET("/tracks", getTracks(db))
	api.GET("/users", getUsers)

	// First time install route, only works when there are no users in the DB yet
	api.POST("/install", install)

	// Authenticated routes
	authorized := api.Group("/")
	authorized.Use(auth)
	{
		authorized.POST("/logout", logout)

		authorized.POST("/tracks", addTrack(db))
		authorized.POST("/tracks/:trackID", updateTrack(db))
		authorized.POST("/tracks/:trackID/publish", publishTrack(db))
		authorized.POST("/tracks/:trackID/claim", claimTrack(db))
		authorized.DELETE("/tracks/:trackID", deleteTrack(db))

		authorized.POST("/users", addUser)
		authorized.POST("/users/:userID", updateUser)
		authorized.POST("/users/:userID/password", updateUserPassword)
	}

	// Fallback route, just sends the frontend index.html
	r.NoRoute(func(c *gin.Context) {
		c.File(path.Join(Config.ThemeDir, "index.html"))
	})

	return r
}

/* Utility
----------------------------------*/
type errorResponse struct {
	Error string `json:"error"`
}

/* Authentication
----------------------------------*/

// Authentication middleware
func auth(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("userID")

	if userID == nil {
		c.Status(403)
		c.Abort()
	} else {
		c.Next()
	}
}

// Remembered user tokens. Do not persist across
// server restarts
var remembered = make([]rememberedLogin, 0)

type rememberedLogin struct {
	userID string
	Token  string
}

/* First time setup
----------------------------------*/
type installRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// Accepts admin user credentials for first-time setup.
// Logs the user in afterwards.
func install(c *gin.Context) {
	if len(UserDatabase.Users) == 0 {
		var requestData installRequest
		c.BindJSON(&requestData)

		if len(requestData.Name) == 0 {
			c.JSON(400, errorResponse{"Invalid name"})
			return
		}

		if len(requestData.Password) < 12 {
			c.JSON(400, errorResponse{"Invalid Password. Minimum length is 12"})
			return
		}

		password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(500, errorResponse{"Something went wrong"})
			return
		}

		hosts := make([]string, 0)
		for _, site := range Config.Sites {
			hosts = append(hosts, site.Hostname)
		}

		id := uuid.NewV4()
		user := IUser{
			id.String(),
			requestData.Name,
			string(password),
			"admin",
			hosts,
		}
		UserDatabase.addUser(user)

		session := sessions.Default(c)
		session.Set("userName", user.Name)
		session.Set("userID", user.ID)
		session.Set("userRole", user.Role)
		session.Set("userHosts", user.Hosts)
		session.Set("userPassword", user.Password)
		session.Save()

		c.JSON(200, authenticatedUserResponse{user.ID, user.Name, user.Role, user.Hosts})
	} else {
		c.JSON(403, errorResponse{"Already set up"})
	}
}

/* Authentication methods
-------------------------------------------*/

type userRequest struct {
	Name     string   `json:"name"`
	Password string   `json:"password"`
	Role     string   `json:"role"`
	Hosts    []string `json:"hosts"`
}

type loginRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

type userResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type authenticatedUserResponse struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Role  string   `json:"role"`
	Hosts []string `json:"hosts"`
}

func login(c *gin.Context) {
	session := sessions.Default(c)
	userIDI := session.Get("userID")
	userNameI := session.Get("userName")
	userRoleI := session.Get("userRole")
	userHostsI := session.Get("userHosts")

	if userIDI != nil {
		userID, ok := userIDI.(string)
		userName := userNameI.(string)
		userRole := userRoleI.(string)
		userHosts := userHostsI.([]string)

		if ok && len(userID) > 0 {
			c.JSON(200, authenticatedUserResponse{userID, userName, userRole, userHosts})
			return
		}
	}

	token, err := c.Cookie("lnb-r")
	if err == nil {
		for _, rToken := range remembered {
			if rToken.Token == token {
				user := UserDatabase.getUserById(rToken.userID)
				if user != nil {
					c.JSON(200, authenticatedUserResponse{user.ID, user.Name, user.Role, user.Hosts})
				}
			}
		}
	}

	var requestData loginRequest
	c.BindJSON(&requestData)

	user := UserDatabase.getUserByName(requestData.Name)
	if user != nil {
		if !user.inHost(c.Request.Host) {
			c.JSON(403, errorResponse{"Invalid login data"})
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(requestData.Password))
		if err == nil {
			session.Set("userName", user.Name)
			session.Set("userID", user.ID)
			session.Set("userRole", user.Role)
			session.Set("userHosts", user.Hosts)
			session.Set("userPassword", user.Password)
			session.Save()

			if requestData.Remember {
				token, err := GenerateRandomString(32)
				if err != nil {
					c.JSON(500, errorResponse{"Something went wrong"})
					return
				}

				oneYearSeconds := 60 * 60 * 24 * 365
				c.SetCookie("lnb-r", token, oneYearSeconds, "/", c.Request.Host, true, true)
				remembered = append(remembered, rememberedLogin{user.ID, token})
				select {
				case <-time.After(time.Duration(oneYearSeconds) * time.Second):
					for i := range remembered {
						r := &remembered[i]
						if r.userID == user.ID {
							remembered = append(remembered[:i], remembered[i+1:]...)
							break
						}
					}
				}
			}

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

/* Track CRUD
----------------------------------*/

type trackRequest struct {
	Artist  string `json:"artist"`
	Title   string `json:"title"`
	Release string `json:"release"`
	URL     string `json:"URL"`
	Start   int    `json:"start"`
	End     int    `json:"end"`
	Meta    string `json:"meta"`
}

func getTracks(db *ITrackDatabase) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("userID")

		if userID != nil {
			c.JSON(200, db.Tracks)
		} else {
			c.JSON(200, db.getPublishedTracks())
		}
	}
}

func addTrack(db *ITrackDatabase) gin.HandlerFunc {
	return func(c *gin.Context) {
		var requestData trackRequest
		c.BindJSON(&requestData)
		session := sessions.Default(c)
		userID := session.Get("userID")

		id := userID.(string)

		if len(requestData.Artist) == 0 {
			c.JSON(400, errorResponse{"Invalid artist"})
			return
		}

		if len(requestData.Title) == 0 {
			c.JSON(400, errorResponse{"Invalid title"})
			return
		}

		if len(requestData.Release) == 0 {
			c.JSON(400, errorResponse{"Invalid release"})
			return
		}

		if len(requestData.URL) == 0 {
			c.JSON(400, errorResponse{"Invalid URL"})
			return
		}

		if requestData.End == 0 {
			c.JSON(400, errorResponse{"End cannot be zero"})
			return
		}

		if len(requestData.Meta) == 0 {
			requestData.Meta = "{}"
		}

		track := ITrack{
			ID:       uuid.NewV4().String(),
			Episode:  nil,
			Artist:   requestData.Artist,
			Title:    requestData.Title,
			Release:  requestData.Release,
			URL:      requestData.URL,
			Start:    requestData.Start,
			End:      requestData.End,
			Meta:     requestData.Meta,
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
		trackID := c.Param("trackID")

		if len(requestData.Artist) == 0 {
			c.JSON(400, errorResponse{"Invalid artist"})
			return
		}

		if len(requestData.Title) == 0 {
			c.JSON(400, errorResponse{"Invalid title"})
			return
		}

		if len(requestData.Release) == 0 {
			c.JSON(400, errorResponse{"Invalid release"})
			return
		}

		if len(requestData.URL) == 0 {
			c.JSON(400, errorResponse{"Invalid URL"})
			return
		}

		if requestData.End == 0 {
			c.JSON(400, errorResponse{"End cannot be zero"})
			return
		}

		if len(requestData.Meta) == 0 {
			requestData.Meta = "{}"
		}

		track := db.getTrackById(trackID)

		if track != nil {
			track.Artist = requestData.Artist
			track.Title = requestData.Title
			track.Release = requestData.Release
			track.URL = requestData.URL
			track.Start = requestData.Start
			track.End = requestData.End
			track.Meta = requestData.Meta
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
		trackID := c.Param("trackID")
		track := db.getTrackById(trackID)

		if track != nil {
			if track.Episode != nil {
				c.JSON(400, errorResponse{"Track already published at episode " + strconv.FormatInt(int64(*track.Episode), 10)})
				return
			}

			latestEpisode := db.getNewEpisodeNumber()
			track.Episode = &latestEpisode
			db.write()
			c.JSON(200, track)
		} else {
			c.JSON(404, errorResponse{"Track not found"})
		}
	}
}

func claimTrack(db *ITrackDatabase) gin.HandlerFunc {
	return func(c *gin.Context) {
		trackID := c.Param("trackID")
		track := db.getTrackById(trackID)

		if track != nil {
			if len(track.Uploader) != 0 {
				c.JSON(400, errorResponse{"Track already claimed"})
				return
			}

			session := sessions.Default(c)
			userID := session.Get("userID")
			userIDstring := userID.(string)
			track.Uploader = userIDstring
			db.write()
			c.JSON(200, track)
		} else {
			c.JSON(404, errorResponse{"Track not found"})
		}
	}
}

func deleteTrack(db *ITrackDatabase) gin.HandlerFunc {
	return func(c *gin.Context) {
		trackID := c.Param("trackID")
		track := db.getTrackById(trackID)

		if track == nil {
			c.JSON(404, errorResponse{"Track not found"})
		} else if track.Episode != nil {
			c.JSON(403, errorResponse{"Track already published"})
		} else {
			deletedTrack := db.deleteTrack(trackID)
			c.JSON(200, *deletedTrack)
		}
	}
}

/* User CRU(D)
----------------------------------*/

func getUsers(c *gin.Context) {
	session := sessions.Default(c)
	userRole := session.Get("userRole")

	if userRole == "admin" {
		response := make([]authenticatedUserResponse, 0)
		for _, user := range UserDatabase.Users {
			if user.inHost(c.Request.Host) {
				response = append(response, authenticatedUserResponse{user.ID, user.Name, user.Role, user.Hosts})
			}
		}
		c.JSON(200, response)
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
		return
	}

	var requestData userRequest
	c.BindJSON(&requestData)

	if len(requestData.Name) == 0 {
		c.JSON(400, errorResponse{"Invalid name"})
		return
	}

	if len(requestData.Password) < 12 {
		c.JSON(400, errorResponse{"Invalid Password. Minimum length is 12"})
		return
	}

	if len(requestData.Role) == 0 || (requestData.Role != "submitter" && requestData.Role != "admin") {
		c.JSON(400, errorResponse{"Invalid Role. Provide either 'admin' or 'submitter'"})
		return
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
		return
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
	userID := c.Param("userID")

	if len(requestData.Name) == 0 {
		c.JSON(400, errorResponse{"Invalid name"})
		return
	}

	if len(requestData.Password) < 12 {
		c.JSON(400, errorResponse{"Invalid Password. Minimum length is 12"})
		return
	}

	user := UserDatabase.getUserById(userID)

	if len(user.Name) > 0 {
		password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(500, errorResponse{"Something went wrong"})
			return
		}

		user.Name = requestData.Name
		user.Password = string(password)
		UserDatabase.write()
	} else {
		c.JSON(404, errorResponse{"User not found"})
	}
}

type passwordUpdateRequest struct {
	CurrentUserPassword string `json:"currentUserPassword"`
	Password            string `json:"password"`
	PasswordRepeat      string `json:"passwordRepeat"`
}

func updateUserPassword(c *gin.Context) {
	session := sessions.Default(c)
	userRole := session.Get("userRole").(string)
	userID := session.Get("userID").(string)
	currUserPassword := session.Get("userPassword").([]byte)
	userToUpdateId := c.Param("userID")
	var requestData passwordUpdateRequest
	c.BindJSON(&requestData)

	err := bcrypt.CompareHashAndPassword(currUserPassword, []byte(requestData.CurrentUserPassword))
	if err != nil {
		c.JSON(403, errorResponse{"Incorrect current password"})
		return
	}

	if userRole == "admin" || userID == userToUpdateId {
		if requestData.Password != requestData.PasswordRepeat {
			c.JSON(400, errorResponse{"Passwords do not match"})
			return
		}

		password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(500, errorResponse{"Something went wrong"})
			return
		}

		user := UserDatabase.getUserById(userID)
		user.Password = string(password)
		UserDatabase.write()

	} else {
		c.JSON(403, errorResponse{"Insufficient rights"})
	}
}
