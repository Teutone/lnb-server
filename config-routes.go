package main

import (
	"encoding/json"
	"net/http"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

/* Templating config
----------------------------------*/
func getConfig(host string) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		var seoConfig SeoConfig
		for _, vConfig := range Config.Sites {
			if vConfig.Hostname == host {
				seoConfig = vConfig.SeoConfig
				break
			}
		}

		json.NewEncoder(w).Encode(seoConfig)
	}
}
func setConfig(host string) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestData SeoConfig
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&requestData)
		defer r.Body.Close()
		if err != nil {
			throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
			return
		}

		for index := range Config.Sites {
			vConfig := &Config.Sites[index]
			if vConfig.Hostname == host {
				vConfig.SeoConfig.DefaultSocialMessage = requestData.DefaultSocialMessage
				vConfig.SeoConfig.InformationText = requestData.InformationText
				vConfig.SeoConfig.Description = requestData.Description
				vConfig.SeoConfig.Description = requestData.Description
				vConfig.SeoConfig.Title = requestData.Title
				writeConfig()
				json.NewEncoder(w).Encode(vConfig.SeoConfig)
				return
			}
		}
	}
}

/* First time setup
----------------------------------*/
type installRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func install(w http.ResponseWriter, r *http.Request) {
	if len(UserDatabase.Users) == 0 {
		var requestData installRequest
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&requestData)
		defer r.Body.Close()
		if err != nil {
			throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
			return
		}

		if len(requestData.Name) == 0 {
			throwError(w, "Invalid name", http.StatusBadRequest)
			return
		}

		if len(requestData.Password) < 12 {
			throwError(w, "Invalid Password. Minimum length is 12", http.StatusBadRequest)
			return
		}

		password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			throwError(w, "Something went wrong", http.StatusInternalServerError)
			return
		}

		hosts := make([]string, 0)
		for _, site := range Config.Sites {
			hosts = append(hosts, site.Hostname)
		}

		id, err := uuid.NewV4()
		if err != nil {
			throwError(w, "Could not generate ID", http.StatusInternalServerError)
		}

		user := IUser{
			id.String(),
			requestData.Name,
			"",
			string(password),
			"admin",
			hosts,
		}
		UserDatabase.addUser(user)
		json.NewEncoder(w).Encode(authenticatedUserResponse{user.ID, user.Name, user.Bio, user.Role, user.Hosts})
	} else {
		throwError(w, "Already set up", http.StatusForbidden)
	}
}
