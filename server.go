package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"

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

type handlerFuncType func(w http.ResponseWriter, r *http.Request)

// Takes the track database and
// The router initializissociated with the host as only argument
func initHostRouter(db *ITrackDatabase, hc *fbHostConfig, r *mux.Router) {
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
	api.Handle("/tracks/{trackID}/publish", mw(http.HandlerFunc(publishTrack(db, hc)), authMiddleware)).
		Methods("POST")
	api.Handle("/tracks/{trackID}/claim", mw(http.HandlerFunc(claimTrack(db)), authMiddleware)).
		Methods("POST")
	api.Handle("/tracks/{trackID}", mw(http.HandlerFunc(deleteTrack(db)), authMiddleware)).
		Methods("DELETE")

	api.Handle("/users/", mw(http.HandlerFunc(addUser(db.Hostname)), adminMiddleware)).
		Methods("POST")
	api.Handle("/users/{userID}", mw(http.HandlerFunc(updateUser), authMiddleware)).
		Methods("POST")

	api.Handle("/fb/getRedirectURL", mw(http.HandlerFunc(fbGetRedirectionURL(hc)), adminMiddleware)).
		Methods("GET")
	api.Handle("/fb/access", mw(http.HandlerFunc(fbGetAccess(hc)), adminMiddleware)).
		Methods("GET")
	api.Handle("/fb/setUserAccessToken", mw(http.HandlerFunc(fbSetUserAccessToken(hc)), adminMiddleware)).
		Methods("POST")
	api.Handle("/fb/setPage", mw(http.HandlerFunc(fbSetPage(hc)), adminMiddleware)).
		Methods("POST")
	api.Handle("/fb/pages", mw(http.HandlerFunc(fbGetPages(hc)), adminMiddleware)).
		Methods("GET")
	api.Handle("/fb", mw(http.HandlerFunc(fbClear(hc)), adminMiddleware)).
		Methods("DELETE")

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
func adminMiddleware(h http.Handler) http.Handler {
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
			return
		}

		userRoleI := session.Values["userRole"]
		userRole, ok := userRoleI.(string)

		if !ok || len(userRole) == 0 || userRole != "admin" {
			throwError(w, "Nuh-uh", http.StatusForbidden)
			return
		}

		h.ServeHTTP(w, r)
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

func login(host string) handlerFuncType {
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
					session.Options.Domain = host + "." // dot added to trick chrome into accepting single dot domains
					session.Options.Secure = true
				}

				if Config.Env == "dev" && len(Config.DevCookieDomain) > 0 {
					session.Options.Domain = Config.DevCookieDomain + "." // dot added to trick chrome into accepting single dot domains
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
