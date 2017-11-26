package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
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

	api.Handle("/config", mw(http.HandlerFunc(getConfig(db.Hostname)), authMiddleware)).
		Methods("GET")
	api.Handle("/config", mw(http.HandlerFunc(setConfig(db.Hostname)), adminMiddleware)).
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

	/* The 404 handler just returns the templated index.html */
	indexFileLocation := path.Join(themeStaticDir, "index.html")
	r.NotFoundHandler = http.HandlerFunc(indexFallback(db, hc, indexFileLocation))
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

/* Index.html fallback
----------------------------------*/
func indexFallback(db *ITrackDatabase, hc *fbHostConfig, file string) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := template.ParseFiles(file)
		if err != nil {
			log.Print(err)
			throwError(w, "Couldn't parse index file", http.StatusInternalServerError)
			return
		}

		data := struct {
			Title       string
			Description string
		}{"", ""}

		var seoConfig SeoConfig
		for _, vConfig := range Config.Sites {
			if vConfig.Hostname == db.Hostname {
				seoConfig = vConfig.SeoConfig
				break
			}
		}

		/* SEO / Opengraph variables */
		path := r.URL.Path[1:]
		if len(path) == 0 {
			latestTrack := db.getLatestTrack()
			data.Title = buildMeta(seoConfig.Title.Episode, latestTrack)
			data.Description = buildMeta(seoConfig.Description.Episode, latestTrack)
		} else {
			episode, err := strconv.Atoi(path)
			if err != nil {
				data.Title = seoConfig.Title.Default
				data.Description = seoConfig.Description.Default
			} else {
				track := db.getTrackByEpisode(episode)
				data.Title = buildMeta(seoConfig.Title.Episode, *track)
				data.Description = buildMeta(seoConfig.Description.Episode, *track)
			}
		}

		t.Execute(w, data)
	}
}
