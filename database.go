package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

type UserType struct {
	Id       string `json: "id"`
	Name     string `json: "id"`
	Password string `json: "password"`
}

type TrackType struct {
	Id      string `json: "id"`
	Episode *int   `json: "episode"`
	Artist  string `json: "artist"`
	Title   string `json: "title"`
	Release string `json: "release"`
	Url     string `json: "url"`
}

type DatabaseType struct {
	Users  []UserType  `json: "users"`
	Tracks []TrackType `json: "tracks"`
}

var Database DatabaseType

func InitDatabase() {
	log.Print("initializing database")
	var path = Config.DatabaseFile
	if path == "" {
		log.Fatal("config.dataDir has to be set")
	}

	var _, err = os.Stat(path)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if isError(err) {
			log.Fatal(err)
		}

		var dbString []byte
		dbString, err = json.Marshal(Database)
		if isError(err) {
			log.Fatal(err)
		}

		file.Write(dbString)
		file.Close()
	}

	databaseContents, err := ioutil.ReadFile(path)
	if isError(err) {
		log.Fatal(err)
	}
	json.Unmarshal(databaseContents, &Database)
}

func GetUserById(id string) UserType {
	var result UserType
	for _, user := range Database.Users {
		if user.Id == id {
			result = user
			break
		}
	}

	return result
}

func GetTrackById(id string) TrackType {
	var result TrackType
	for _, track := range Database.Tracks {
		if track.Id == id {
			result = track
			break
		}
	}

	return result
}

func GetTrackByEpisode(episode int) TrackType {
	var result TrackType
	for _, track := range Database.Tracks {
		if track.Episode == nil {
			continue
		}

		if *track.Episode == episode {
			result = track
			break
		}
	}

	return result
}
