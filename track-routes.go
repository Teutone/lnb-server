package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
)

/* Track CRUD
----------------------------------*/

// Used for track adding and updating
type trackRequest struct {
	Artist  string `json:"artist"`
	Title   string `json:"title"`
	Release string `json:"release"`
	URL     string `json:"url"`
	Start   int    `json:"start"`
	End     int    `json:"end"`
	Meta    string `json:"meta"`
}

/* Gets the current track list
 *
 * If logged in, the user gets all tracks,
 * if not, just the published ones.
 *
 *******************************************/
func getTracks(db *ITrackDatabase) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userIDI := session.Values["userID"]
		if userIDI != nil {
			userID, ok := userIDI.(string)
			if ok && len(userID) > 0 {
				json.NewEncoder(w).Encode(db.Tracks)
				return
			}
		}
		json.NewEncoder(w).Encode(db.getPublishedTracks())
	}
}

/* Adds a track
 *
 * Does super basic validation,
 * I don't care what you choose to put in your files
 *
 **************************************************/
func addTrack(db *ITrackDatabase) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {

		// Get request body
		var requestData trackRequest
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&requestData) != nil {
			throwError(w, fmt.Sprintf("Sent JSON body does is not of correct type"), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if len(requestData.Artist) == 0 {
			throwError(w, "Invalid artist", http.StatusBadRequest)
			return
		}

		if len(requestData.Title) == 0 {
			throwError(w, "Invalid title", http.StatusBadRequest)
			return
		}

		if len(requestData.Release) == 0 {
			throwError(w, "Invalid release", http.StatusBadRequest)
			return
		}

		if len(requestData.URL) == 0 {
			throwError(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		if requestData.End == 0 {
			throwError(w, "End cannot be zero", http.StatusBadRequest)
			return
		}

		if len(requestData.Meta) == 0 {
			requestData.Meta = "{}"
		}

		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userIDI := session.Values["userID"]
		userID, ok := userIDI.(string)
		if !ok {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		id, err := uuid.NewV4()
		if err != nil {
			throwError(w, "Could not generate ID", http.StatusInternalServerError)
		}
		track := ITrack{
			ID:              id.String(),
			Episode:         nil,
			Artist:          requestData.Artist,
			Title:           requestData.Title,
			Release:         requestData.Release,
			URL:             requestData.URL,
			Start:           requestData.Start,
			End:             requestData.End,
			Meta:            requestData.Meta,
			Uploader:        userID,
			LastChangeStamp: time.Now().Unix(),
		}
		db.addTrack(track)

		json.NewEncoder(w).Encode(track)
	}
}

/* Update track
 *
 * Updates a track, whether published or unpublished
 *
 ******************************************************/
func updateTrack(db *ITrackDatabase) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestData trackRequest
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&requestData)
		defer r.Body.Close()
		if err != nil {
			throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
			return
		}
		params := mux.Vars(r)
		trackID := params["trackID"]

		if len(requestData.Artist) == 0 {
			throwError(w, "Invalid artist", http.StatusBadRequest)
			return
		}

		if len(requestData.Title) == 0 {
			throwError(w, "Invalid title", http.StatusBadRequest)
			return
		}

		if len(requestData.Release) == 0 {
			throwError(w, "Invalid release", http.StatusBadRequest)
			return
		}

		if len(requestData.URL) == 0 {
			throwError(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		if requestData.End == 0 {
			throwError(w, "End cannot be zero", http.StatusBadRequest)
			return
		}

		if len(requestData.Meta) == 0 {
			requestData.Meta = "{}"
		}

		track := db.getTrackById(trackID)

		if track != nil {
			track.Artist = requestData.Artist
			track.Title = requestData.Title
			track.Release = requestData.Release
			track.URL = requestData.URL
			track.Start = requestData.Start
			track.End = requestData.End
			track.Meta = requestData.Meta
			track.LastChangeStamp = time.Now().Unix()
			db.write()

			json.NewEncoder(w).Encode(*track)
		} else {
			throwError(w, "Track not found", http.StatusNotFound)
		}
	}
}

/* Publishes a track with given ID
 *
 ***************************************/
type publishTrackRequest struct {
	Message string `json:"message"`
}

func publishTrack(db *ITrackDatabase, hc *fbHostConfig) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestData publishTrackRequest
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&requestData)
		defer r.Body.Close()
		if err != nil {
			throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
			return
		}
		params := mux.Vars(r)
		trackID := params["trackID"]
		track := db.getTrackById(trackID)

		if track != nil {
			if track.Episode != nil {
				epString := strconv.FormatInt(int64(*track.Episode), 10)
				throwError(w, "Track already published at episode "+epString, http.StatusForbidden)
				return
			}

			latestEpisode := db.getNewEpisodeNumber()
			track.Episode = &latestEpisode
			track.LastChangeStamp = time.Now().Unix()
			db.write()
			err = hc.postToPage(requestData.Message, *track)
			if err != nil {
				log.Printf("Couldn't post to facebook: %s", err.Error())
				log.Printf("verbose error info: %#v", err)
			}
			json.NewEncoder(w).Encode(track)
		} else {
			throwError(w, "Track not found", http.StatusNotFound)
		}
	}
}

/* Claims a track
 *
 * Used for legacy Databases, users can say if they uploaded this track
 *
 ***************************************/
func claimTrack(db *ITrackDatabase) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		trackID := params["trackID"]
		track := db.getTrackById(trackID)

		if track != nil {
			if len(track.Uploader) != 0 {
				throwError(w, "Track already claimed", http.StatusBadRequest)
				return
			}

			session, err := store.Get(r, DefaultSession)
			if err != nil {
				throwError(w, err.Error(), http.StatusInternalServerError)
				return
			}

			userID := session.Values["userID"]
			userIDstring := userID.(string)
			track.Uploader = userIDstring
			track.LastChangeStamp = time.Now().Unix()
			db.write()
			json.NewEncoder(w).Encode(track)
		} else {
			throwError(w, "Track not found", http.StatusNotFound)
		}
	}
}

func deleteTrack(db *ITrackDatabase) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		trackID := params["trackID"]
		track := db.getTrackById(trackID)

		if track == nil {
			throwError(w, "Track not found", http.StatusNotFound)
		} else if track.Episode != nil {
			throwError(w, "Track already published", http.StatusForbidden)
		} else {
			deletedTrack := db.deleteTrack(trackID)
			json.NewEncoder(w).Encode(*deletedTrack)
		}
	}
}
