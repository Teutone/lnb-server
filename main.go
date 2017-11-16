package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	// Read in the config file location from the cli arguments
	configFile := os.Args[1]
	if len(configFile) == 0 {
		log.Fatal("Please specify the config file location as the first cli argument")
	}

	InitConfig(configFile)
	InitUserDatabase()

	router := mux.NewRouter()

	// Loop over the hosts defined in the config so we can setup the vhosts
	hostnames := make([]string, 0)
	for _, vConfig := range Config.Sites {
		trackDb := InitTrackDatabase(vConfig.Hostname)
		vRouter := router.Host(vConfig.Hostname).Subrouter()
		InitHostRouter(trackDb, vRouter)
		hostnames = append(hostnames, vConfig.Hostname)
	}

	handler := handlers.LoggingHandler(os.Stdout, handlers.CompressHandler(router))

	if Config.LetsEncryptEnabled {
		// Setup letsencrypt manager
		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hostnames...),
			Cache:      autocert.DirCache("/var/www/.cache"),
			Email:      Config.LetsEncryptEmail,
		}
		s := &http.Server{
			Addr:         ":https",
			TLSConfig:    &tls.Config{GetCertificate: m.GetCertificate},
			Handler:      handler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}

		log.Fatal(s.ListenAndServeTLS("", ""))
	} else {
		// No letsencrypt; just listen on the specified port
		portString := strconv.FormatInt(int64(Config.Port), 10)
		log.Println("Listening on port :" + portString)
		log.Fatal(http.ListenAndServe(":"+portString, handler))
	}
}
