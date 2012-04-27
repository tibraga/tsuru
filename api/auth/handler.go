package auth

import (
	"encoding/json"
	"fmt"
	"github.com/timeredbull/tsuru/db"
	"github.com/timeredbull/tsuru/errors"
	"io/ioutil"
	"net/http"
	"strings"
)

func CheckToken(token string) (*User, error) {
	if token == "" {
		return nil, &errors.Http{Code: http.StatusBadRequest, Message: "You must provide the Authorization header"}
	}
	u, err := GetUserByToken(token)
	if err != nil {
		return nil, &errors.Http{Code: http.StatusUnauthorized, Message: "Invalid token"}
	}
	return u, nil
}

func CreateUser(w http.ResponseWriter, r *http.Request) error {
	var u User
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(b, &u)
	if err != nil {
		return &errors.Http{Code: http.StatusBadRequest, Message: err.Error()}
	}
	err = u.Create()
	if err == nil {
		w.WriteHeader(http.StatusCreated)
		return nil
	}

	if u.Get() == nil {
		err = &errors.Http{Code: http.StatusConflict, Message: "This email is already registered"}
	}

	return err
}

func Login(w http.ResponseWriter, r *http.Request) error {
	var pass map[string]string
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(b, &pass)
	if err != nil {
		return &errors.Http{Code: http.StatusBadRequest, Message: "Invalid JSON"}
	}

	password, ok := pass["password"]
	if !ok {
		msg := "You must provide a password to login"
		return &errors.Http{Code: http.StatusBadRequest, Message: msg}
	}

	u := User{Email: r.URL.Query().Get(":email")}
	err = u.Get()
	if err != nil {
		return &errors.Http{Code: http.StatusNotFound, Message: "User not found"}
	}

	if u.Login(password) {
		t, _ := u.CreateToken()
		fmt.Fprintf(w, `{"token":"%s"}`, t.Token)
		return nil
	}

	msg := "Authentication failed, wrong password"
	return &errors.Http{Code: http.StatusUnauthorized, Message: msg}
}

func CheckAuthorization(w http.ResponseWriter, r *http.Request) error {
	token := r.Header.Get("Authorization")
	user, err := CheckToken(token)
	if err != nil {
		return err
	}
	output := map[string]string{
		"email": user.Email,
	}
	b, err := json.Marshal(output)
	if err != nil {
		return err
	}
	w.Write(b)
	return nil
}

func CreateTeam(w http.ResponseWriter, r *http.Request, u *User) error {
	var params map[string]string
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(b, &params)
	if err != nil {
		return &errors.Http{Code: http.StatusBadRequest, Message: err.Error()}
	}
	name, ok := params["name"]
	if !ok {
		msg := "You must provide the team name"
		return &errors.Http{Code: http.StatusBadRequest, Message: msg}
	}
	team := &Team{Name: name, Users: []*User{u}}
	err = db.Session.Teams().Insert(team)
	if err != nil && strings.Contains(err.Error(), "duplicate key error") {
		return &errors.Http{Code: http.StatusConflict, Message: "This team already exists"}
	}
	return nil
}
