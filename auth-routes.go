package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

/* Authentication Methods
-------------------------------------------*/

type userRequest struct {
	Name     string   `json:"name"`
	Bio      string   `json:"bio"`
	Password string   `json:"password"`
	Role     string   `json:"role"`
	Hosts    []string `json:"hosts"`
}

type loginRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

type userResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Bio  string `json:"bio"`
}

type authenticatedUserResponse struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Bio   string   `json:"bio"`
	Role  string   `json:"role"`
	Hosts []string `json:"hosts"`
}

func login(host string) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		// Short term session
		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userIDI := session.Values["userID"]
		userNameI := session.Values["userName"]
		userBioI := session.Values["userBio"]
		userRoleI := session.Values["userRole"]
		userHostsI := session.Values["userHosts"]

		if userIDI != nil {
			userID, ok := userIDI.(string)
			userName := userNameI.(string)
			userBio := userBioI.(string)
			userRole := userRoleI.(string)
			userHosts := userHostsI.([]string)

			if ok && len(userID) > 0 {
				json.NewEncoder(w).Encode(authenticatedUserResponse{userID, userName, userBio, userRole, userHosts})
				return
			}
		}

		// Get request body
		var requestData loginRequest
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&requestData) != nil {
			throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		user := UserDatabase.getUserByName(requestData.Name)
		if user != nil {
			if !user.inHost(host) {
				throwError(w, "Invalid login data", http.StatusForbidden)
				return
			}

			err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(requestData.Password))
			if err == nil {
				session.Values["version"] = DefaultSessionVersion
				session.Values["userName"] = user.Name
				session.Values["userID"] = user.ID
				session.Values["userBio"] = user.Bio
				session.Values["userRole"] = user.Role
				session.Values["userHosts"] = user.Hosts
				session.Values["userPassword"] = user.Password
				session.Options = &sessions.Options{
					Path:     "/",
					Secure:   false,
					HttpOnly: false,
					MaxAge:   60 * 60,
				}

				if Config.env == "production" {
					// session.Options.Domain = host
					session.Options.Secure = true
				}

				if requestData.Remember {
					oneYear := 60 * 60 * 24 * 365
					session.Options.MaxAge = oneYear
				}

				err = session.Save(r, w)
				if err != nil {
					throwError(w, err.Error(), http.StatusInternalServerError)
					return
				}
				json.NewEncoder(w).Encode(authenticatedUserResponse{user.ID, user.Name, user.Bio, user.Role, user.Hosts})
				return
			}
		}

		throwError(w, "Invalid login data", http.StatusForbidden)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, DefaultSession)
	if err != nil {
		throwError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["userID"] = nil
	session.Values["userName"] = nil
	session.Values["userRole"] = nil
	session.Values["userHosts"] = nil
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		throwError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(struct{}{})
}
