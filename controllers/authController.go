package controllers

import (
	"encoding/json"
	"gocontacts/models"
	u "gocontacts/utils"
	"net/http"
)

// CreateAccount -
var CreateAccount = func(w http.ResponseWriter, r *http.Request) {

	account := &models.Account{}
	err := json.NewDecoder(r.Body).Decode(account)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request from create new"))
		return
	}

	resp := account.Create()
	u.Respond(w, resp)
}

// Authenticate -
var Authenticate = func(w http.ResponseWriter, r *http.Request) {

	account := &models.Account{}
	err := json.NewDecoder(r.Body).Decode(account)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	resp := models.Login(account.Email, account.Password)
	u.Respond(w, resp)
}
