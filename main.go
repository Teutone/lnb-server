package main

import (
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func main() {
	// Read in the config file location from the cli arguments
	configFile := os.Args[1]
	if len(configFile) == 0 {
		log.Fatal("Please specify the config file location as the first cli argument")
	}

	initConfig(configFile)
	initUserDatabase()
	initFb()
	initCookieStore()

	router := mux.NewRouter()

	// Loop over the hosts defined in the config so we can setup the vhosts
	for _, vConfig := range Config.Sites {
		trackDb := initTrackDatabase(vConfig.Hostname)
		vRouter := router.Host(vConfig.Hostname).Subrouter()
		hc := getFbConfigForHost(vConfig.Hostname)
		initHostRouter(trackDb, hc, vRouter)
	}

	handler := handlers.LoggingHandler(os.Stdout, handlers.CompressHandler(router))

	// No letsencrypt; just listen on the specified port
	portString := strconv.FormatInt(int64(Config.Port), 10)
	log.Println("Listening on port :" + portString)
	log.Fatal(http.ListenAndServe(":"+portString, handler))
}
