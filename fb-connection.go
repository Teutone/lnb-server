package main

import (
	"fmt"
	"log"
	"strconv"

	fb "github.com/huandu/facebook"
)

var fbApp *fb.App

type fbAccess struct {
	LocalUserID     string `json:"localUserId"`
	UserAccessToken string `json:"userAccessToken"`
	PageID          string `json:"pageId"`
	PageName        string `json:"pageName"`
	PageAccessToken string `json:"pageAccessToken"`
}

type fbHostConfig struct {
	access      *fbAccess
	host        string
	userSession *fb.Session
	pageSession *fb.Session
}

func initFb() {

	fbApp = fb.New(Config.FbAppID, Config.FbAppSecret)
	// fbApp.RedirectUri = "http://" + Config.Sites[0].Hostname + "/admin/fb/connect"
}

func getFbConfigForHost(host string) *fbHostConfig {
	hostConfig := fbHostConfig{
		nil,
		host,
		nil,
		nil,
	}
	for index := range Config.Sites {
		site := &Config.Sites[index]
		if site.Hostname == host {
			hostConfig.access = &site.FbConfig
			break
		}
	}

	if hostConfig.access == nil || len(hostConfig.access.UserAccessToken) == 0 {
		return &hostConfig
	}

	err := hostConfig.initUserSession()
	if err == nil {
		err = hostConfig.initPageSession()
		if err != nil {
			log.Printf("Page session for host %s did not validate", host)
		}
	} else {
		log.Printf("User session for host %s did not validate", host)
	}

	return &hostConfig
}

func (hc *fbHostConfig) clear() {
	hc.access = nil
	hc.pageSession = nil
	hc.userSession = nil

	for index := range Config.Sites {
		site := &Config.Sites[index]
		if site.Hostname == hc.host {
			site.FbConfig = fbAccess{"", "", "", "", ""}
			hc.access = &site.FbConfig
			break
		}
	}

	writeConfig()
}

func (hc *fbHostConfig) getFbLoginRedirect() string {
	state, err := GenerateRandomString(12)

	if err != nil {
		return ""
	}

	return fmt.Sprintf(
		"https://www.facebook.com/v2.11/dialog/oauth?client_id=%s&&state=%s&scope=%s&response_type=%s",
		Config.FbAppID,
		state,
		"manage_pages,publish_pages",
		"token",
	)
}

func (hc *fbHostConfig) initUserSession() error {
	hc.userSession = fbApp.Session(hc.access.UserAccessToken)
	hc.userSession.EnableAppsecretProof(true)
	return hc.userSession.Validate()
}

func (hc *fbHostConfig) setUserAccessToken(userAccessToken string, userID string) error {
	hc.clear()
	hc.access.LocalUserID = userID
	res, err := fb.Get("/oauth/access_token", fb.Params{
		"grant_type":        "fb_exchange_token",
		"client_id":         Config.FbAppID,
		"client_secret":     Config.FbAppSecret,
		"fb_exchange_token": userAccessToken,
	})
	if err != nil {
		log.Printf("An error occurred during token exchange: %v", err)
		return err
	}

	hc.access.UserAccessToken = res.Get("access_token").(string)
	err = hc.initUserSession()
	writeConfig()
	return err
}

func (hc *fbHostConfig) initPageSession() error {
	hc.pageSession = fbApp.Session(hc.access.PageAccessToken)
	hc.pageSession.EnableAppsecretProof(true)
	return hc.pageSession.Validate()
}

type facebookPage struct {
	Name        string `facebook:"name,required" json:"name"`
	AccessToken string `facebook:"access_token,required" json:"accessToken"`
	ID          string `facebook:",required" json:"id"`
}

func (hc *fbHostConfig) getPages() ([]facebookPage, error) {
	res, err := hc.userSession.Get("/me/accounts", nil)
	if err != nil {
		hc.clear()
		return nil, err
	}
	var pages []facebookPage
	res.DecodeField("data", &pages)
	return pages, nil
}

func (hc *fbHostConfig) setPage(pageID string, pageName string, pageAccessToken string) error {
	hc.access.PageID = pageID
	hc.access.PageName = pageName
	hc.access.PageAccessToken = pageAccessToken
	err := hc.initPageSession()
	writeConfig()
	return err
}

func (hc *fbHostConfig) postToPage(message string, track ITrack) error {
	if hc.pageSession == nil {
		log.Println("pageSession empty, not posting")
		return nil
	}

	epString := strconv.FormatInt(int64(*track.Episode), 10)
	protocol := "http"
	if Config.env == "production" {
		protocol = "https"
	}
	link := protocol + "://" + hc.host + "/" + epString

	messageToSend := ""
	for index := range Config.Sites {
		site := &Config.Sites[index]
		if site.Hostname == hc.host {
			messageToSend = buildMeta(site.SeoConfig.DefaultSocialMessage, track)
			break
		}
	}

	if len(message) != 0 {
		messageToSend = fmt.Sprintf("%s\n\n%s", message, messageToSend)
	}

	log.Printf("Printing message to facebook page %s: \n\n%s\n\n%s", hc.access.PageID, messageToSend, link)

	pagePostURL := fmt.Sprintf("/%s/feed", hc.access.PageID)
	_, err := hc.pageSession.Post(pagePostURL, fb.Params{
		"message": messageToSend,
		"link":    link,
	})
	return err
}
