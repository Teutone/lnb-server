package main

import (
	"encoding/json"
	"log"
	"net/http"
	"path"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

// The cookie store
var store *sessions.CookieStore

const (
	SessionName = "lnb-session"
)

// Remembered user tokens. Do not persist across
// server restarts
var remembered = make([]rememberedLogin, 0)

type rememberedLogin struct {
	userID string
	Token  string
}

type HandlerFuncType func(w http.ResponseWriter, r *http.Request)

// Takes the track database a
// The router initializissociated with the host as only argument
func InitHostRouter(db *ITrackDatabase, r *mux.Router) {
	log.Print("initializing router for host " + db.Hostname)

	// Sessions
	store = sessions.NewCookieStore([]byte(Config.SessionKey))

	// Api set-up and routes
	api := mux.NewRouter()
	r.PathPrefix("/api").Handler(http.StripPrefix("/api", mw(api, setContentTypeMiddleware)))

	// Unauthenticated API routes
	api.HandleFunc("/login", login).
		Methods("POST")
	api.HandleFunc("/tracks", getTracks(db)).
		Methods("GET")
	api.HandleFunc("/users", getUsers).
		Methods("GET")

	// First time install route, only works when there are no users in the DB yet
	api.HandleFunc("/install", install).
		Methods("POST")

	// Authenticated routes
	// So what's happening here is kind of confusing:

	// all of these routes require the authMiddleware middleware,
	// So we use the mw() func to put it in front of our actual handler
	// the mw function returns a http.Handler, which is why we use api.Handle().

	// The directly used funcs (e.g. logout) are of type func(http.ResponseWriter, http.Request)
	// the executed funcs (e.g. addTrack(db)) are ones that require the track database for the current host,
	// so they are wrapped in another func that returns a func of the above type.

	// http.HandlerFunc is a convenience method to turn the above func type into a http.Handler

	api.Handle("/logout", mw(http.HandlerFunc(logout), authMiddleware)).
		Methods("POST")

	api.Handle("/tracks", mw(http.HandlerFunc(addTrack(db)), authMiddleware)).
		Methods("POST")
	api.Handle("/tracks/:trackID", mw(http.HandlerFunc(updateTrack(db)), authMiddleware)).
		Methods("POST")
	api.Handle("/tracks/:trackID/publish", mw(http.HandlerFunc(publishTrack(db)), authMiddleware)).
		Methods("POST")
	api.Handle("/tracks/:trackID/claim", mw(http.HandlerFunc(claimTrack(db)), authMiddleware)).
		Methods("POST")
	api.Handle("/tracks/:trackID", mw(http.HandlerFunc(deleteTrack(db)), authMiddleware)).
		Methods("DELETE")

	api.Handle("/users", mw(http.HandlerFunc(addUser), authMiddleware)).
		Methods("POST")
	api.Handle("/users/:userID", mw(http.HandlerFunc(updateUser), authMiddleware)).
		Methods("POST")
	api.Handle("/users/:userID/password", mw(http.HandlerFunc(updateUserPassword), authMiddleware)).
		Methods("POST")

	/* Static files */
	themeStaticDir := path.Join(Config.ThemeDir, db.Hostname)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir(themeStaticDir)))

	/* The 404 handler just returns the index.html */
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path.Join(themeStaticDir, "index.html"))
	})
}

/* Utility
----------------------------------*/
type errorResponse struct {
	Error string `json:"error"`
}

func mw(h http.Handler, adapters ...func(http.Handler) http.Handler) http.Handler {
	for _, adapter := range adapters {
		h = adapter(h)
	}
	return h
}

/* Middleware
----------------------------------*/

// Content-Type json
func setContentTypeMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		h.ServeHTTP(w, r)
	})
}

// Authentication
func authMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, SessionName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userIDI := session.Values["userID"]
		userID, ok := userIDI.(string)

		if !ok || len(userID) == 0 {
			// not allowed
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

/* First time setup
----------------------------------*/
type installRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// Accepts admin user credentials for first-time setup.
// Logs the user in afterwards.
func install(w http.ResponseWriter, r *http.Request) {
	if len(UserDatabase.Users) == 0 {
		var requestData installRequest
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&requestData) != nil {
			http.Error(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
		}
		defer r.Body.Close()

		if len(requestData.Name) == 0 {
			http.Error(w, "Invalid name", http.StatusBadRequest)
			return
		}

		if len(requestData.Password) < 12 {
			http.Error(w, "Invalid Password. Minimum length is 12", http.StatusBadRequest)
			return
		}

		password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
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

		session, err := store.Get(r, SessionName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session.Values["userName"] = user.Name
		session.Values["userID"] = user.ID
		session.Values["userRole"] = user.Role
		session.Values["userHosts"] = user.Hosts
		session.Values["userPassword"] = user.Password
		session.Save(r, w)

		json.NewEncoder(w).Encode(authenticatedUserResponse{user.ID, user.Name, user.Role, user.Hosts})
	} else {
		http.Error(w, "Already set up", http.StatusForbidden)
	}
}

/* Authentication Methods
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

func login(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, SessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userIDI := session.Values["userID"]
	userNameI := session.Values["userName"]
	userRoleI := session.Values["userRole"]
	userHostsI := session.Values["userHosts"]

	if userIDI != nil {
		userID, ok := userIDI.(string)
		userName := userNameI.(string)
		userRole := userRoleI.(string)
		userHosts := userHostsI.([]string)

		if ok && len(userID) > 0 {
			json.NewEncoder(w).Encode(authenticatedUserResponse{userID, userName, userRole, userHosts})
			return
		}
	}

	token, err := c.Cookie("lnb-r")
	if err == nil {
		for _, rToken := range remembered {
			if rToken.Token == token {
				user := UserDatabase.getUserById(rToken.userID)
				if user != nil {
					json.NewEncoder(w).Encode(authenticatedUserResponse{user.ID, user.Name, user.Role, user.Hosts})
				}
			}
		}
	}

	// Get request body
	var requestData loginRequest
	decoder := json.NewDecoder(r.Body)
	if decoder.Decode(&requestData) != nil {
		http.Error(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
	}
	defer r.Body.Close()

	user := UserDatabase.getUserByName(requestData.Name)
	if user != nil {
		if !user.inHost(r.Host) {
			http.Error(w, "Invalid login data", http.StatusForbidden)
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(requestData.Password))
		if err == nil {
			session.Values["userName"] = user.Name
			session.Values["userID"] = user.ID
			session.Values["userRole"] = user.Role
			session.Values["userHosts"] = user.Hosts
			session.Values["userPassword"] = user.Password
			session.Save(r, w)

			/* if requestData.Remember {
				token, err := GenerateRandomString(32)
				if err != nil {
					http.Error(w, "Something went wrong", http.StatusInternalServerError)
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
			} */

			json.NewEncoder(w).Encode(authenticatedUserResponse{user.ID, user.Name, user.Role, user.Hosts})
			return
		}
	}

	http.Error(w, "Invalid login data", http.StatusForbidden)
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, SessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Clear()
	session.Save(r, w)
	json.NewEncoder(w).Encode(struct{}{})
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

func getTracks(db *ITrackDatabase) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, SessionName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userIDI := session.Values["userID"]
		if userIDI != nil {
			userID, ok := userIDI.(string)
			if ok && len(userID) > 0 {
				// send full data
				return
			}
		}
		// send half the data
	}
}

func addTrack(db *ITrackDatabase) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {

		// Get request body
		var requestData trackRequest
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&requestData) != nil {
			http.Error(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
		}
		defer r.Body.Close()

		if len(requestData.Artist) == 0 {
			http.Error(w, "Invalid artist", http.StatusBadRequest)
			return
		}

		if len(requestData.Title) == 0 {
			http.Error(w, "Invalid title", http.StatusBadRequest)
			return
		}

		if len(requestData.Release) == 0 {
			http.Error(w, "Invalid release", http.StatusBadRequest)
			return
		}

		if len(requestData.URL) == 0 {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		if requestData.End == 0 {
			http.Error(w, "End cannot be zero", http.StatusBadRequest)
			return
		}

		if len(requestData.Meta) == 0 {
			requestData.Meta = "{}"
		}

		session, err := store.Get(r, SessionName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userIDI := session.Values["userID"]
		var userID string
		if userIDI != nil {
			userID, ok := userIDI.(string)
			if !ok {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
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
			Uploader: userID,
		}
		db.addTrack(track)

		json.NewEncoder(w).Encode(track)
	}
}

func updateTrack(db *ITrackDatabase) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get request body
		var requestData trackRequest
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&requestData) != nil {
			http.Error(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
		}
		defer r.Body.Close()
		params := mux.Vars(r)
		trackID := params["trackID"]

		if len(requestData.Artist) == 0 {
			http.Error(w, "Invalid artist", http.StatusBadRequest)
			return
		}

		if len(requestData.Title) == 0 {
			http.Error(w, "Invalid title", http.StatusBadRequest)
			return
		}

		if len(requestData.Release) == 0 {
			http.Error(w, "Invalid release", http.StatusBadRequest)
			return
		}

		if len(requestData.URL) == 0 {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		if requestData.End == 0 {
			http.Error(w, "End cannot be zero", http.StatusBadRequest)
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

			json.NewEncoder(w).Encode(*track)
		} else {
			http.Error(w, "Track not found", http.StatusNotFound)
		}
	}
}

func publishTrack(db *ITrackDatabase) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		trackID := params["trackID"]
		track := db.getTrackById(trackID)

		if track != nil {
			if track.Episode != nil {
				epString := strconv.FormatInt(int64(*track.Episode), 10)
				http.Error(w, "Track already published at episode "+epString, http.StatusForbidden)
				return
			}

			latestEpisode := db.getNewEpisodeNumber()
			track.Episode = &latestEpisode
			db.write()
			json.NewEncoder(w).Encode(track)
		} else {
			http.Error(w, "Track not found", http.StatusNotFound)
		}
	}
}

func claimTrack(db *ITrackDatabase) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		trackID := params["trackID"]
		track := db.getTrackById(trackID)

		if track != nil {
			if len(track.Uploader) != 0 {
				http.Error(w, "Track already claimed", http.StatusBadRequest)
				return
			}

			session, err := store.Get(r, SessionName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			userID := session.Values["userID"]
			userIDstring := userID.(string)
			track.Uploader = userIDstring
			db.write()
			json.NewEncoder(w).Encode(track)
		} else {
			http.Error(w, "Track not found", http.StatusNotFound)
		}
	}
}

func deleteTrack(db *ITrackDatabase) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		trackID := params["trackID"]
		track := db.getTrackById(trackID)

		if track == nil {
			http.Error(w, "Track not found", http.StatusNotFound)
		} else if track.Episode != nil {
			http.Error(w, "Track already published", http.StatusForbidden)
		} else {
			deletedTrack := db.deleteTrack(trackID)
			json.NewEncoder(w).Encode(*deletedTrack)
		}
	}
}

/* User CRU(D)
----------------------------------*/

func getUsers(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, SessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userRole := session.Values["userRole"]

	if userRole == "admin" {
		response := make([]authenticatedUserResponse, 0)
		for _, user := range UserDatabase.Users {
			if user.inHost(r.Host) {
				response = append(response, authenticatedUserResponse{user.ID, user.Name, user.Role, user.Hosts})
			}
		}
		json.NewEncoder(w).Encode(response)
	} else {
		response := make([]userResponse, 0)
		for _, user := range UserDatabase.Users {
			if user.inHost(r.Host) {
				response = append(response, userResponse{user.ID, user.Name})
			}
		}
		json.NewEncoder(w).Encode(response)
	}
}

func addUser(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, SessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userRole := session.Values["userRole"]

	if userRole != "admin" {
		http.Error(w, "Insufficient rights", http.StatusForbidden)
		return
	}

	// Get request body
	var requestData userRequest
	decoder := json.NewDecoder(r.Body)
	if decoder.Decode(&requestData) != nil {
		http.Error(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(requestData.Name) == 0 {
		http.Error(w, "Invalid name", http.StatusBadRequest)
		return
	}

	if len(requestData.Password) < 12 {
		http.Error(w, "Invalid Password. Minimum length is 12", http.StatusBadRequest)
		return
	}

	if len(requestData.Role) == 0 || (requestData.Role != "submitter" && requestData.Role != "admin") {
		http.Error(w, "Invalid Role. Provide either 'admin' or 'submitter'", http.StatusBadRequest)
		return
	}

	if len(requestData.Hosts) == 0 {
		requestData.Hosts = append(requestData.Hosts, r.Host)
	}

	user := UserDatabase.getUserByName(requestData.Name)

	if len(user.Name) > 0 {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
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

	json.NewEncoder(w).Encode(userResponse{newUser.ID, newUser.Name})
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	// Get request body
	var requestData userRequest
	decoder := json.NewDecoder(r.Body)
	if decoder.Decode(&requestData) != nil {
		http.Error(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
	}
	defer r.Body.Close()
	params := mux.Vars(r)
	userID := params["userID"]

	if len(requestData.Name) == 0 {
		http.Error(w, "Invalid name", http.StatusBadRequest)
		return
	}

	if len(requestData.Password) < 12 {
		http.Error(w, "Invalid Password. Minimum length is 12", http.StatusBadRequest)
		return
	}

	user := UserDatabase.getUserById(userID)

	if len(user.Name) > 0 {
		password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}

		user.Name = requestData.Name
		user.Password = string(password)
		UserDatabase.write()
		json.NewEncoder(w).Encode(authenticatedUserResponse{user.ID, user.Name, user.Role, user.Hosts})
	} else {
		http.Error(w, "User not found", http.StatusNotFound)
	}
}

type passwordUpdateRequest struct {
	CurrentUserPassword string `json:"currentUserPassword"`
	Password            string `json:"password"`
	PasswordRepeat      string `json:"passwordRepeat"`
}

func updateUserPassword(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, SessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userRole := session.Values["userRole"].(string)
	userID := session.Values["userID"].(string)
	currUserPassword := session.Values["userPassword"].([]byte)

	params := mux.Vars(r)
	userToUpdateID := params["userID"]

	// Get request body
	var requestData passwordUpdateRequest
	decoder := json.NewDecoder(r.Body)
	if decoder.Decode(&requestData) != nil {
		http.Error(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
	}
	defer r.Body.Close()

	if bcrypt.CompareHashAndPassword(currUserPassword, []byte(requestData.CurrentUserPassword)) != nil {
		http.Error(w, "Incorrect current password", http.StatusForbidden)
		return
	}

	if userRole == "admin" || userID == userToUpdateID {
		if requestData.Password != requestData.PasswordRepeat {
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			return
		}

		password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}

		user := UserDatabase.getUserById(userToUpdateID)
		user.Password = string(password)
		UserDatabase.write()
		json.NewEncoder(w).Encode(authenticatedUserResponse{user.ID, user.Name, user.Role, user.Hosts})
	} else {
		http.Error(w, "Insufficient rights", http.StatusForbidden)
	}
}
