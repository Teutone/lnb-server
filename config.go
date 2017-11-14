package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

type SiteConfig struct {
	Hostname string `json:"hostname"`
	Theme    string `json:"theme"`
}

type ServerConfig struct {
	LetsEncryptEnabled bool   `json:"letsEncryptEnabled"`
	LetsEncryptEmail   string `json:"letsEncryptEmail"`
	Port               int    `json:"port"`
	DataDir            string `json:"dataDir"`
	ThemeDir           string `json:"themeDir"`
	SessionKey         string `json:"sessionKey"`
	Sites              []SiteConfig
}

var Config ServerConfig

func InitConfig(file string) {
	log.Print("reading config from " + file)
	configFile, err := ioutil.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			log.Fatal("config file does not exist")
		} else {
			log.Fatal("Config file could not be read")
		}
	}
	json.Unmarshal(configFile, &Config)
}
