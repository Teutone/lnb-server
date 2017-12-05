package main

import (
	"encoding/json"
	"net/http"
)

type fbRedirectResponse struct {
	URL string `json:"url"`
}

func fbGetRedirectionURL(hc *fbHostConfig) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(fbRedirectResponse{hc.getFbLoginRedirect()})
	}
}

type fbSetUserRequest struct {
	UserAccessToken string `json:"userAccessToken"`
}

func fbSetUserAccessToken(hc *fbHostConfig) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestData fbSetUserRequest
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&requestData)
		defer r.Body.Close()
		if err != nil {
			throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
			return
		}

		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		currUserIDI := session.Values["userID"]
		currUserID, ok := currUserIDI.(string)
		if !ok {
			throwError(w, "Insufficient rights", http.StatusForbidden)
			return
		}

		err = hc.setUserAccessToken(requestData.UserAccessToken, currUserID)

		if err != nil {
			throwError(w, "User access does not seem to work: "+err.Error(), http.StatusExpectationFailed)
			return
		}

		json.NewEncoder(w).Encode(hc.access)
	}
}

func fbGetPages(hc *fbHostConfig) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		currUserIDI := session.Values["userID"]
		currUserID, ok := currUserIDI.(string)
		if !ok || currUserID != hc.access.LocalUserID {
			throwError(w, "Insufficient rights", http.StatusForbidden)
			return
		}

		pages, err := hc.getPages()
		if err != nil {
			throwError(w, err.Error(), http.StatusExpectationFailed)
			return
		}

		json.NewEncoder(w).Encode(pages)
	}
}

type accessResponse struct {
	LocalUserID string `json:"localUserId"`
	PageName    string `json:"pageName"`
	PageID      string `json:"pageId"`
}

func fbGetAccess(hc *fbHostConfig) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		res := accessResponse{
			hc.access.LocalUserID,
			hc.access.PageName,
			hc.access.PageID,
		}
		json.NewEncoder(w).Encode(res)
	}
}

type fbSetPageRequest struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	AccessToken string `json:"accessToken"`
}

func fbSetPage(hc *fbHostConfig) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, DefaultSession)
		if err != nil {
			throwError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		currUserIDI := session.Values["userID"]
		currUserID, ok := currUserIDI.(string)
		if !ok || currUserID != hc.access.LocalUserID {
			throwError(w, "Insufficient rights", http.StatusForbidden)
			return
		}

		var requestData fbSetPageRequest
		decoder := json.NewDecoder(r.Body)
		err = decoder.Decode(&requestData)
		defer r.Body.Close()
		if err != nil {
			throwError(w, "Sent JSON body does is not of correct type", http.StatusBadRequest)
			return
		}

		err = hc.setPage(requestData.ID, requestData.Name, requestData.AccessToken)
		if err != nil {
			throwError(w, "Page access does not seem to work: "+err.Error(), http.StatusExpectationFailed)
			return
		}

		json.NewEncoder(w).Encode(hc.access)
	}
}

func fbClear(hc *fbHostConfig) handlerFuncType {
	return func(w http.ResponseWriter, r *http.Request) {
		hc.clear()
		json.NewEncoder(w).Encode(struct{}{})
	}
}
