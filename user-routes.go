package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

/* User CRU(D)
----------------------------------*/

func getUsers(host string) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userRole := session.Values["userRole"]

		if userRole == "admin" {
			response := make([]authenticatedUserResponse, 0)
			for _, user := range UserDatabase.Users {
				if user.inHost(host) {
					response = append(response, authenticatedUserResponse{user.ID, user.Name, user.Bio, user.Role, user.Hosts})
				}
			}
			json.NewEncoder(w).Encode(response)
		} else {
			response := make([]userResponse, 0)
			for _, user := range UserDatabase.Users {
				if user.inHost(host) {
					response = append(response, userResponse{user.ID, user.Name, user.Bio})
				}
			}
			json.NewEncoder(w).Encode(response)
		}
	}
}

func addUser(host string) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestData userRequest
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&requestData) != nil {
			throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if len(requestData.Name) == 0 {
			throwError(w, "Invalid name", http.StatusBadRequest)
			return
		}

		if len(requestData.Password) < 12 {
			throwError(w, "Invalid Password. Minimum length is 12", http.StatusBadRequest)
			return
		}

		if len(requestData.Role) == 0 || (requestData.Role != "submitter" && requestData.Role != "admin") {
			throwError(w, "Invalid Role. Provide either 'admin' or 'submitter'", http.StatusBadRequest)
			return
		}

		if len(requestData.Hosts) == 0 {
			requestData.Hosts = append(requestData.Hosts, host)
		}

		user := UserDatabase.getUserByName(requestData.Name)

		if user != nil {
			throwError(w, "User already exists", http.StatusBadRequest)
			return
		}

		password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			throwError(w, "Something went wrong", http.StatusInternalServerError)
			return
		}

		id, err := uuid.NewV4()
		if err != nil {
			throwError(w, "Could not generate ID", http.StatusInternalServerError)
		}

		newUser := IUser{
			id.String(),
			requestData.Name,
			requestData.Bio,
			string(password),
			requestData.Role,
			requestData.Hosts,
		}
		UserDatabase.addUser(newUser)

		json.NewEncoder(w).Encode(userResponse{newUser.ID, newUser.Name, newUser.Bio})
	}
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	var requestData userRequest
	decoder := json.NewDecoder(r.Body)
	if decoder.Decode(&requestData) != nil {
		throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
	}
	defer r.Body.Close()
	params := mux.Vars(r)
	userID := params["userID"]

	session, err := store.Get(r, DefaultSession)
	if err != nil {
		throwError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	currUserIDI := session.Values["userID"]
	currUserID, ok := currUserIDI.(string)
	currUserRole := session.Values["userRole"].(string)
	if !ok || (currUserID != userID && currUserRole != "admin") {
		throwError(w, "Insufficient rights", http.StatusForbidden)
		return
	}

	if len(requestData.Name) == 0 {
		throwError(w, "Invalid name", http.StatusBadRequest)
		return
	}

	user := UserDatabase.getUserById(userID)

	if len(user.Name) > 0 {
		if len(requestData.Password) > 0 {
			if len(requestData.Password) < 12 {
				throwError(w, "Invalid Password. Minimum length is 12", http.StatusBadRequest)
				return
			}

			password, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
			if err != nil {
				throwError(w, "Something went wrong", http.StatusInternalServerError)
				return
			}
			user.Password = string(password)
		}

		if currUserRole == "admin" {
			user.Role = requestData.Role
			user.Hosts = requestData.Hosts
		}

		user.Name = requestData.Name
		user.Bio = requestData.Bio
		UserDatabase.write()
		json.NewEncoder(w).Encode(authenticatedUserResponse{user.ID, user.Name, user.Bio, user.Role, user.Hosts})
	} else {
		throwError(w, "User not found", http.StatusNotFound)
	}
}
