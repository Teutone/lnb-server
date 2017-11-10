package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

var r *mux.Router

func Serve() {
	log.Print("initializing server")
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

	protectedRouter := csrf.Protect([]byte(Config.AuthKey))(r)
	http.Handle("/", protectedRouter)
	var portString = strconv.FormatInt(int64(Config.Port), 10)

	log.Print("listening on port " + portString)
	err := http.ListenAndServe(":"+portString, nil)
	if err != nil {
		log.Fatal(err)
	}
}

// Utility
func Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("middleware", r.URL)
		h.ServeHTTP(w, r)
	})
}

// General

func getCsrfToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
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
