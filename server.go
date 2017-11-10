package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

var r *mux.Router
var store *sessions.CookieStore

func Serve() {
	log.Print("initializing server")
	// Creates a router without any middleware by default
	r := gin.New()

	// Global middleware
	// Logger middleware will write the logs to gin.DefaultWriter even you set with GIN_MODE=release.
	// By default gin.DefaultWriter = os.Stdout
	r.Use(gin.Logger())

	// Recovery middleware recovers from any panics and writes a 500 if there was one.
	r.Use(gin.Recovery())

	// Per route middleware, you can add as many as you desire.
	r.GET("/benchmark", MyBenchLogger(), benchEndpoint)

	// Authorization group
	// authorized := r.Group("/", AuthRequired())
	// exactly the same as:
	authorized := r.Group("/")
	// per group middleware! in this case we use the custom created
	// AuthRequired() middleware just in the "authorized" group.
	authorized.Use(AuthRequired())
	{
		authorized.POST("/login", loginEndpoint)
		authorized.POST("/submit", submitEndpoint)
		authorized.POST("/read", readEndpoint)

		// nested group
		testing := authorized.Group("testing")
		testing.GET("/analytics", analyticsEndpoint)
	}

	// Listen and serve on 0.0.0.0:8080
	r.Run(":8080")

	r = mux.NewRouter()

	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/csrfToken", getCsrfToken).
		Methods("GET").
		Host(Config.Hostname)

	api.HandleFunc("/playlist", getPlaylist).
		Methods("GET").
		Host(Config.Hostname)
	api.HandleFunc("/queue", getQueue).
		Methods("GET").
		Host(Config.Hostname)

	api.HandleFunc("/tracks", addTrack).
		Methods("POST").
		Host(Config.Hostname)
	api.HandleFunc("/tracks/{trackId}", updateTrack).
		Methods("POST").
		Host(Config.Hostname)
	api.HandleFunc("/tracks/{trackId}/publish", publishTrack).
		Methods("POST").
		Host(Config.Hostname)
	api.HandleFunc("/tracks/{trackId}", deleteTrack).
		Methods("DELETE").
		Host(Config.Hostname)

	api.HandleFunc("/users", getUsers).
		Methods("GET").
		Host(Config.Hostname)
	api.HandleFunc("/users", addUser).
		Methods("POST").
		Host(Config.Hostname)
	api.HandleFunc("/users/{trackId}", updateUser).
		Methods("POST").
		Host(Config.Hostname)

	r.PathPrefix("/").Handler(http.FileServer(http.Dir(Config.ThemeDir)))

	protectedRouter := csrf.Protect([]byte(Config.CsrfKey))(r)
	store = sessions.NewCookieStore([]byte(Config.SessionKey))
	http.Handle("/", protectedRouter)
	var portString = strconv.FormatInt(int64(Config.Port), 10)

	log.Print("listening on port " + portString)
	err := http.ListenAndServe(":"+portString, nil)
	if err != nil {
		log.Fatal(err)
	}
}

// Utility
func setContentType(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		h.ServeHTTP(w, r)
	})
}
func auth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "")
		log.Println("middleware", r.URL)
		h.ServeHTTP(w, r)
	})
}

func logRequest(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("middleware", r.URL)
		h.ServeHTTP(w, r)
	})
}

// General

func getCsrfToken(w http.ResponseWriter, r *http.Request) {
	payload := []byte("{\"csrftoken\":\"" + csrf.Token(r) + "\"}")
	w.Write(payload)
}

func getPlaylist(w http.ResponseWriter, r *http.Request) {
	fmt.Println("getPlaylist")
}

func getQueue(w http.ResponseWriter, r *http.Request) {
	fmt.Println("getQueue")
}

// Tracks

func addTrack(w http.ResponseWriter, r *http.Request) {
	fmt.Println("addTrack")

}

func updateTrack(w http.ResponseWriter, r *http.Request) {
	fmt.Println("updateTrack")

}

func publishTrack(w http.ResponseWriter, r *http.Request) {
	fmt.Println("publishTrack")

}

func deleteTrack(w http.ResponseWriter, r *http.Request) {
	fmt.Println("deleteTrack")

}

// Users

func getUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("getUsers")

}

func addUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("addUser")

}

func updateUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("updateUser")

}
