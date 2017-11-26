package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
)

type SeoConfig struct {
	InformationText      string `json:"informationText"`
	DefaultSocialMessage string `json:"defaultSocialMessage"`
	Description          struct {
		Episode string `json:"episode"`
		Default string `json:"default"`
	} `json:"description"`
	Title struct {
		Episode string `json:"episode"`
		Default string `json:"default"`
	} `json:"title"`
}

type SiteConfig struct {
	Hostname  string    `json:"hostname"`
	Theme     string    `json:"theme"`
	FbConfig  fbAccess  `json:"fbConfig"`
	SeoConfig SeoConfig `json:"seo"`
}

type ServerConfig struct {
	Env                string `json:"env"`
	DevCookieDomain    string `json:"devCookieDomain"`
	LetsEncryptEnabled bool   `json:"letsEncryptEnabled"`
	LetsEncryptEmail   string `json:"letsEncryptEmail"`
	Port               int    `json:"port"`
	DataDir            string `json:"dataDir"`
	ThemeDir           string `json:"themeDir"`
	SessionKey         string `json:"sessionKey"`
	FbAppID            string `json:"fbAppId"`
	FbAppSecret        string `json:"fbAppSecret"`
	Sites              []SiteConfig
}

var Config ServerConfig
var configLocation string

func initConfig(file string) {
	configLocation = file

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

	if Config.Env != "dev" && Config.Env != "prod" {
		log.Fatal("Please set the config \"env\" key to either \"dev\" or \"prod\"")
	}
}

func writeConfig() {
	log.Println("writing config")

	configString, err := json.MarshalIndent(&Config, "", "    ")
	if err != nil {
		log.Fatal(err)
	}

	ioutil.WriteFile(configLocation, configString, 0666)
	configContents, err := ioutil.ReadFile(configLocation)
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal(configContents, &Config)
}

func buildMeta(input string, track ITrack) string {
	epString := strconv.FormatInt(int64(*track.Episode), 10)
	output := strings.Replace(input, "$$ARTIST", track.Artist, -1)
	output = strings.Replace(output, "$$TITLE", track.Title, -1)
	output = strings.Replace(output, "$$RELEASE", track.Release, -1)
	output = strings.Replace(output, "$$EPISODE", epString, -1)
	return output
}
