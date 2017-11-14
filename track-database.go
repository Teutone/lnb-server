package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path"
)

type ITrack struct {
	ID       string `json:"id"`
	Episode  *int   `json:"episode"`
	Artist   string `json:"artist"`
	Title    string `json:"title"`
	Release  string `json:"release"`
	URL      string `json:"url"`
	Uploader string `json:"uploader"`
}

type ITrackDatabase struct {
	File     string
	Hostname string
	Tracks   []ITrack
}

func InitTrackDatabase(hostname string) *ITrackDatabase {
	log.Print("initializing track database for host " + hostname)

	if Config.DataDir == "" {
		log.Fatal("config.dataDir has to be set // tracks")
	}

	database := ITrackDatabase{
		path.Join(Config.DataDir, hostname+".json"),
		hostname,
		make([]ITrack, 0),
	}

	var _, err = os.Stat(database.File)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(database.File)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		var dbString []byte
		dbString, err = json.Marshal(&database.Tracks)
		if err != nil {
			log.Fatal(err)
		}

		_, err = file.Write(dbString)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		databaseContents, err := ioutil.ReadFile(database.File)
		if err != nil {
			log.Fatal(err)
		}
		json.Unmarshal(databaseContents, &database.Tracks)
	}
	return &database
}

func (db *ITrackDatabase) write() {
	log.Print("writing track database file for host " + db.Hostname)

	dbString, err := json.Marshal(&db.Tracks)
	if err != nil {
		log.Fatal(err)
	}

	ioutil.WriteFile(db.File, dbString, 0666)
	databaseContents, err := ioutil.ReadFile(db.File)
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal(databaseContents, &db.Tracks)
}

func (db *ITrackDatabase) getTrackById(id string) *ITrack {
	var result *ITrack
	for i := range db.Tracks {
		track := &db.Tracks[i]
		if track.ID == id {
			result = track
			break
		}
	}

	return result
}

func (db *ITrackDatabase) getNewEpisodeNumber() int {
	var latestEpisode = -1

	for i := range db.Tracks {
		track := &db.Tracks[i]
		if track.Episode != nil && *track.Episode > latestEpisode {
			latestEpisode = *track.Episode
			break
		}
	}
	latestEpisode = latestEpisode + 1
	return latestEpisode
}

func (db *ITrackDatabase) getPublishedTracks() []*ITrack {
	result := make([]*ITrack, 0)
	for i := range db.Tracks {
		track := &db.Tracks[i]
		if track.Episode != nil {
			result = append(result, track)
		}
	}

	return result
}

func (db *ITrackDatabase) addTrack(track ITrack) {
	db.Tracks = append(db.Tracks, track)
	db.write()
}

func (db *ITrackDatabase) deleteTrack(id string) *ITrack {
	var result *ITrack
	for i := range db.Tracks {
		track := &db.Tracks[i]
		if track.ID == id {
			result = track
			db.Tracks = append(db.Tracks[:i], db.Tracks[i+1:]...)
			break
		}
	}

	return result
}
