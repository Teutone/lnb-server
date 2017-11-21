package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

// The cookie store
var store *sessions.CookieStore

const (
	DefaultSession        = "lnb-session"
	DefaultSessionVersion = 1
)

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
	api.HandleFunc("/login", login(db.Hostname)).
		Methods("POST")
	api.HandleFunc("/logout", logout).
		Methods("POST")
	api.HandleFunc("/tracks/", getTracks(db)).
		Methods("GET")
	api.HandleFunc("/users/", getUsers(db.Hostname)).
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

	api.Handle("/tracks/", mw(http.HandlerFunc(addTrack(db)), authMiddleware)).
		Methods("POST")
	api.Handle("/tracks/{trackID}", mw(http.HandlerFunc(updateTrack(db)), authMiddleware)).
		Methods("POST")
	api.Handle("/tracks/{trackID}/publish", mw(http.HandlerFunc(publishTrack(db)), authMiddleware)).
		Methods("POST")
	api.Handle("/tracks/{trackID}/claim", mw(http.HandlerFunc(claimTrack(db)), authMiddleware)).
		Methods("POST")
	api.Handle("/tracks/{trackID}", mw(http.HandlerFunc(deleteTrack(db)), authMiddleware)).
		Methods("DELETE")

	api.Handle("/users/", mw(http.HandlerFunc(addUser(db.Hostname)), authMiddleware)).
		Methods("POST")
	api.Handle("/users/{userID}", mw(http.HandlerFunc(updateUser), authMiddleware)).
		Methods("POST")

	api.Handle("/fb/connect-start", mw(http.HandlerFunc(updateUser), authMiddleware)).
		Methods("GET")
	api.Handle("/fb/connect-finish", mw(http.HandlerFunc(updateUser), authMiddleware)).
		Methods("GET")
	api.Handle("/fb/disconnect", mw(http.HandlerFunc(updateUser), authMiddleware)).
		Methods("GET")

	/* Static files */
	themeStaticDir := path.Join(Config.ThemeDir, db.Hostname)
	log.Printf("serving static on /static/ from %s", themeStaticDir)
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static", http.FileServer(http.Dir(themeStaticDir))))

	/* The 404 handler just returns the index.html */
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path.Join(themeStaticDir, "index.html"))
	})
}

/* Utility
----------------------------------*/

func mw(h http.Handler, adapters ...func(http.Handler) http.Handler) http.Handler {
	for _, adapter := range adapters {
		h = adapter(h)
	}
	return h
}

func throwError(w http.ResponseWriter, message string, code int) {
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, message)
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
		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userIDI := session.Values["userID"]
		userID, ok := userIDI.(string)

		if !ok || len(userID) == 0 {
			throwError(w, "Nuh-uh", http.StatusForbidden)
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
			throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if len(requestData.Name) == 0 {
			throwError(w, "Invalid name", http.StatusBadRequest)
			return
		}

		if len(requestData.Password) < 12 {
			throwError(w, "Invalid Password. Minimum length is 12", http.StatusBadRequest)
			return
		}

		password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			throwError(w, "Something went wrong", http.StatusInternalServerError)
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
			"",
			string(password),
			"admin",
			hosts,
		}
		UserDatabase.addUser(user)

		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session.Values["version"] = DefaultSessionVersion
		session.Values["userName"] = user.Name
		session.Values["userBio"] = user.Bio
		session.Values["userID"] = user.ID
		session.Values["userRole"] = user.Role
		session.Values["userHosts"] = user.Hosts
		session.Values["userPassword"] = user.Password
		session.Save(r, w)

		json.NewEncoder(w).Encode(authenticatedUserResponse{user.ID, user.Name, user.Bio, user.Role, user.Hosts})
	} else {
		throwError(w, "Already set up", http.StatusForbidden)
	}
}

/* Authentication Methods
-------------------------------------------*/

type userRequest struct {
	Name     string   `json:"name"`
	Bio      string   `json:"bio"`
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
	Bio  string `json:"bio"`
}

type authenticatedUserResponse struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Bio   string   `json:"bio"`
	Role  string   `json:"role"`
	Hosts []string `json:"hosts"`
}

func login(host string) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		// Short term session
		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userIDI := session.Values["userID"]
		userNameI := session.Values["userName"]
		userBioI := session.Values["userBio"]
		userRoleI := session.Values["userRole"]
		userHostsI := session.Values["userHosts"]

		if userIDI != nil {
			userID, ok := userIDI.(string)
			userName := userNameI.(string)
			userBio := userBioI.(string)
			userRole := userRoleI.(string)
			userHosts := userHostsI.([]string)

			if ok && len(userID) > 0 {
				json.NewEncoder(w).Encode(authenticatedUserResponse{userID, userName, userBio, userRole, userHosts})
				return
			}
		}

		// Get request body
		var requestData loginRequest
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&requestData) != nil {
			throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		user := UserDatabase.getUserByName(requestData.Name)
		if user != nil {
			if !user.inHost(host) {
				throwError(w, "Invalid login data", http.StatusForbidden)
				return
			}

			err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(requestData.Password))
			if err == nil {
				session.Values["version"] = DefaultSessionVersion
				session.Values["userName"] = user.Name
				session.Values["userID"] = user.ID
				session.Values["userBio"] = user.Bio
				session.Values["userRole"] = user.Role
				session.Values["userHosts"] = user.Hosts
				session.Values["userPassword"] = user.Password
				session.Options = &sessions.Options{
					Path:     "/",
					Secure:   false,
					HttpOnly: false,
				}

				if Config.Env == "prod" {
					session.Options.Domain = host
					session.Options.Secure = true
				}

				if Config.Env == "dev" && len(Config.DevCookieDomain) > 0 {
					session.Options.Domain = Config.DevCookieDomain
				}

				if requestData.Remember {
					oneYear := 60 * 60 * 24 * 365
					session.Options.MaxAge = oneYear
				}

				session.Save(r, w)
				json.NewEncoder(w).Encode(authenticatedUserResponse{user.ID, user.Name, user.Bio, user.Role, user.Hosts})
				return
			}
		}

		throwError(w, "Invalid login data", http.StatusForbidden)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, DefaultSession)
	if err != nil {
		throwError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["userID"] = nil
	session.Values["userName"] = nil
	session.Values["userRole"] = nil
	session.Values["userHosts"] = nil
	session.Options.MaxAge = -1
	session.Save(r, w)
	json.NewEncoder(w).Encode(struct{}{})
}

/* Track CRUD
----------------------------------*/

// Used for track adding and updating
type trackRequest struct {
	Artist  string `json:"artist"`
	Title   string `json:"title"`
	Release string `json:"release"`
	URL     string `json:"url"`
	Start   int    `json:"start"`
	End     int    `json:"end"`
	Meta    string `json:"meta"`
}

/* Gets the current track list
 *
 * If logged in, the user gets all tracks,
 * if not, just the published ones.
 *
 *******************************************/
func getTracks(db *ITrackDatabase) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userIDI := session.Values["userID"]
		if userIDI != nil {
			userID, ok := userIDI.(string)
			if ok && len(userID) > 0 {
				json.NewEncoder(w).Encode(db.Tracks)
				return
			}
		}
		json.NewEncoder(w).Encode(db.getPublishedTracks())
	}
}

/* Adds a track
 *
 * Does super basic validation,
 * I don't care what you choose to put in your files
 *
 **************************************************/
func addTrack(db *ITrackDatabase) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {

		// Get request body
		var requestData trackRequest
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&requestData) != nil {
			throwError(w, fmt.Sprintf("Sent JSON body does is not of correct type"), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if len(requestData.Artist) == 0 {
			throwError(w, "Invalid artist", http.StatusBadRequest)
			return
		}

		if len(requestData.Title) == 0 {
			throwError(w, "Invalid title", http.StatusBadRequest)
			return
		}

		if len(requestData.Release) == 0 {
			throwError(w, "Invalid release", http.StatusBadRequest)
			return
		}

		if len(requestData.URL) == 0 {
			throwError(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		if requestData.End == 0 {
			throwError(w, "End cannot be zero", http.StatusBadRequest)
			return
		}

		if len(requestData.Meta) == 0 {
			requestData.Meta = "{}"
		}

		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userIDI := session.Values["userID"]
		userID, ok := userIDI.(string)
		if !ok {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		track := ITrack{
			ID:              uuid.NewV4().String(),
			Episode:         nil,
			Artist:          requestData.Artist,
			Title:           requestData.Title,
			Release:         requestData.Release,
			URL:             requestData.URL,
			Start:           requestData.Start,
			End:             requestData.End,
			Meta:            requestData.Meta,
			Uploader:        userID,
			LastChangeStamp: time.Now().Unix(),
		}
		db.addTrack(track)

		json.NewEncoder(w).Encode(track)
	}
}

/* Update track
 *
 * Updates a track, whether published or unpublished
 *
 ******************************************************/
func updateTrack(db *ITrackDatabase) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get request body
		var requestData trackRequest
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&requestData) != nil {
			throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		params := mux.Vars(r)
		trackID := params["trackID"]

		if len(requestData.Artist) == 0 {
			throwError(w, "Invalid artist", http.StatusBadRequest)
			return
		}

		if len(requestData.Title) == 0 {
			throwError(w, "Invalid title", http.StatusBadRequest)
			return
		}

		if len(requestData.Release) == 0 {
			throwError(w, "Invalid release", http.StatusBadRequest)
			return
		}

		if len(requestData.URL) == 0 {
			throwError(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		if requestData.End == 0 {
			throwError(w, "End cannot be zero", http.StatusBadRequest)
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
			track.LastChangeStamp = time.Now().Unix()
			db.write()

			json.NewEncoder(w).Encode(*track)
		} else {
			throwError(w, "Track not found", http.StatusNotFound)
		}
	}
}

/* Publishes a track with given ID
 *
 ***************************************/
func publishTrack(db *ITrackDatabase) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		trackID := params["trackID"]
		track := db.getTrackById(trackID)

		if track != nil {
			if track.Episode != nil {
				epString := strconv.FormatInt(int64(*track.Episode), 10)
				throwError(w, "Track already published at episode "+epString, http.StatusForbidden)
				return
			}

			latestEpisode := db.getNewEpisodeNumber()
			track.Episode = &latestEpisode
			track.LastChangeStamp = time.Now().Unix()
			db.write()
			json.NewEncoder(w).Encode(track)
		} else {
			throwError(w, "Track not found", http.StatusNotFound)
		}
	}
}

/* Claims a track
 *
 * Used for legacy Databases, users can say if they uploaded this track
 *
 ***************************************/
func claimTrack(db *ITrackDatabase) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		trackID := params["trackID"]
		track := db.getTrackById(trackID)

		if track != nil {
			if len(track.Uploader) != 0 {
				throwError(w, "Track already claimed", http.StatusBadRequest)
				return
			}

			session, err := store.Get(r, DefaultSession)
			if err != nil {
				throwError(w, err.Error(), http.StatusInternalServerError)
				return
			}

			userID := session.Values["userID"]
			userIDstring := userID.(string)
			track.Uploader = userIDstring
			track.LastChangeStamp = time.Now().Unix()
			db.write()
			json.NewEncoder(w).Encode(track)
		} else {
			throwError(w, "Track not found", http.StatusNotFound)
		}
	}
}

func deleteTrack(db *ITrackDatabase) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		trackID := params["trackID"]
		track := db.getTrackById(trackID)

		if track == nil {
			throwError(w, "Track not found", http.StatusNotFound)
		} else if track.Episode != nil {
			throwError(w, "Track already published", http.StatusForbidden)
		} else {
			deletedTrack := db.deleteTrack(trackID)
			json.NewEncoder(w).Encode(*deletedTrack)
		}
	}
}

/* User CRU(D)
----------------------------------*/

func getUsers(host string) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userRole := session.Values["userRole"]

		if userRole == "admin" {
			response := make([]authenticatedUserResponse, 0)
			for _, user := range UserDatabase.Users {
				if user.inHost(host) {
					response = append(response, authenticatedUserResponse{user.ID, user.Name, user.Bio, user.Role, user.Hosts})
				}
			}
			json.NewEncoder(w).Encode(response)
		} else {
			response := make([]userResponse, 0)
			for _, user := range UserDatabase.Users {
				if user.inHost(host) {
					response = append(response, userResponse{user.ID, user.Name, user.Bio})
				}
			}
			json.NewEncoder(w).Encode(response)
		}
	}
}

func addUser(host string) HandlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userRole := session.Values["userRole"]

		if userRole != "admin" {
			throwError(w, "Insufficient rights", http.StatusForbidden)
			return
		}

		// Get request body
		var requestData userRequest
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&requestData) != nil {
			throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if len(requestData.Name) == 0 {
			throwError(w, "Invalid name", http.StatusBadRequest)
			return
		}

		if len(requestData.Password) < 12 {
			throwError(w, "Invalid Password. Minimum length is 12", http.StatusBadRequest)
			return
		}

		if len(requestData.Role) == 0 || (requestData.Role != "submitter" && requestData.Role != "admin") {
			throwError(w, "Invalid Role. Provide either 'admin' or 'submitter'", http.StatusBadRequest)
			return
		}

		if len(requestData.Hosts) == 0 {
			requestData.Hosts = append(requestData.Hosts, host)
		}

		user := UserDatabase.getUserByName(requestData.Name)

		if user != nil {
			throwError(w, "User already exists", http.StatusBadRequest)
			return
		}

		password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			throwError(w, "Something went wrong", http.StatusInternalServerError)
			return
		}

		id := uuid.NewV4()
		newUser := IUser{
			id.String(),
			requestData.Name,
			requestData.Bio,
			string(password),
			requestData.Role,
			requestData.Hosts,
		}
		UserDatabase.addUser(newUser)

		json.NewEncoder(w).Encode(userResponse{newUser.ID, newUser.Name, newUser.Bio})
	}
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	var requestData userRequest
	decoder := json.NewDecoder(r.Body)
	if decoder.Decode(&requestData) != nil {
		throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
	}
	defer r.Body.Close()
	params := mux.Vars(r)
	userID := params["userID"]

	session, err := store.Get(r, DefaultSession)
	if err != nil {
		throwError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	currUserRole := session.Values["userRole"]
	currUserID := session.Values["userID"]
	if currUserID != userID && currUserRole != "admin" {
		throwError(w, "Insufficient rights", http.StatusForbidden)
		return
	}

	if len(requestData.Name) == 0 {
		throwError(w, "Invalid name", http.StatusBadRequest)
		return
	}

	if len(requestData.Password) < 12 {
		throwError(w, "Invalid Password. Minimum length is 12", http.StatusBadRequest)
		return
	}

	user := UserDatabase.getUserById(userID)

	if len(user.Name) > 0 {
		if len(requestData.Password) > 0 {
			password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
			if err != nil {
				throwError(w, "Something went wrong", http.StatusInternalServerError)
				return
			}
			user.Password = string(password)
		}

		if currUserRole == "admin" {
			user.Role = requestData.Role
			user.Hosts = requestData.Hosts
		}

		user.Name = requestData.Name
		user.Bio = requestData.Bio
		UserDatabase.write()
		json.NewEncoder(w).Encode(authenticatedUserResponse{user.ID, user.Name, user.Bio, user.Role, user.Hosts})
	} else {
		throwError(w, "User not found", http.StatusNotFound)
	}
}
