package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

type ConfigType struct {
	Port         int    `json: "port"`
	Hostname     string `json: "hostname"`
	DatabaseFile string `json: "databaseFile"`
	ThemeDir     string `json: "themeDir"`
	CsrfKey      string `json: "csrfKey"`
	SessionKey   string `json: "sessionKey"`
}

var Config ConfigType

func InitConfig(file string) {
	log.Print("reading config")
	configFile, err := ioutil.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {

		} else {
			fmt.Print("Config file could not be read")
			os.Exit(2)
		}
	}
	json.Unmarshal(configFile, &Config)
}
