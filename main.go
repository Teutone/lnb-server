package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	configFile := os.Args[1]

	if len(configFile) == 0 {
		log.Fatal("Please specify the config file location as the first cli argument")
	}

	InitConfig(configFile)
	InitUserDatabase()
	hostnames := make([]string, 0)
	var vhosts vHosts
	for _, vhost := range Config.Sites {
		trackDb := InitTrackDatabase(vhost.Hostname)
		ginEngine := GetRouter(trackDb)
		vhosts = append(vhosts, vHost{vhost.Hostname, ginEngine})
		hostnames = append(hostnames, vhost.Hostname)
	}

	if Config.LetsEncryptEnabled {
		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hostnames...),
			Cache:      autocert.DirCache("/var/www/.cache"),
			Email:      Config.LetsEncryptEmail,
		}
		s := &http.Server{
			Addr:         ":https",
			TLSConfig:    &tls.Config{GetCertificate: m.GetCertificate},
			Handler:      vhosts,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}

		log.Fatal(s.ListenAndServeTLS("", ""))
	} else {
		portString := strconv.FormatInt(int64(Config.Port), 10)
		log.Println("Listening on port :" + portString)
		log.Fatal(http.ListenAndServe(":"+portString, vhosts))
	}
}

type vHost struct {
	hostname  string
	ginEngine *gin.Engine
}

type vHosts []vHost

func (vhs vHosts) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, vhost := range vhs {
		if vhost.hostname == r.Host {
			vhost.ginEngine.ServeHTTP(w, r)
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 Not Found"))
}
