package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path"
)

type IUser struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Password string   `json:"password"`
	Role     string   `json:"role"`
	Hosts    []string `json:"hosts"`
}

func (u *IUser) inHost(hostname string) bool {
	for _, host := range u.Hosts {
		if host == hostname {
			return true
		}
	}

	return false
}

type IUserDatabase struct {
	File  string
	Users []IUser
}

var UserDatabase IUserDatabase

func InitUserDatabase() {
	log.Print("initializing user database")

	if Config.DataDir == "" {
		log.Fatal("config.dataDir has to be set")
	}

	UserDatabase = IUserDatabase{
		path.Join(Config.DataDir, "users.json"),
		make([]IUser, 0),
	}

	var _, err = os.Stat(UserDatabase.File)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(UserDatabase.File)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		var dbString []byte
		dbString, err = json.Marshal(&UserDatabase.Users)
		if err != nil {
			log.Fatal(err)
		}

		file.Write(dbString)
	} else {
		databaseContents, err := ioutil.ReadFile(UserDatabase.File)
		if err != nil {
			log.Fatal(err)
		}
		json.Unmarshal(databaseContents, &UserDatabase.Users)
	}
}

func (db *IUserDatabase) write() {
	log.Print("writing user database file")

	dbString, err := json.Marshal(&db.Users)
	if err != nil {
		log.Fatal(err)
	}

	ioutil.WriteFile(db.File, dbString, 0666)
	databaseContents, err := ioutil.ReadFile(UserDatabase.File)
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal(databaseContents, &UserDatabase.Users)
}

func (db *IUserDatabase) getUserById(id string) *IUser {
	var result *IUser
	for i := range db.Users {
		user := &db.Users[i]
		if user.ID == id {
			result = user
			break
		}
	}

	return result
}

func (db *IUserDatabase) getUserByName(name string) *IUser {
	var result *IUser
	for i := range db.Users {
		user := &db.Users[i]
		if user.Name == name {
			result = user
			break
		}
	}

	return result
}

func (db *IUserDatabase) addUser(user IUser) {
	db.Users = append(db.Users, user)
	db.write()
}
