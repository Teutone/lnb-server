package main

import (
	"fmt"

	fb "github.com/huandu/facebook"
)

var FbApp *fb.App

func initFb() {
	FbApp = fb.New(Config.FbAppId, Config.FbAppSecret)
	FbApp.RedirectUri = "https://" + Config.Sites[0].Hostname + "/admin/fb-connect"
}

func getFbLoginRedirect() (string, error) {
	state, err := GenerateRandomString(12)

	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"https://www.facebook.com/v2.11/dialog/oauth?client_id=%s&redirect_uri=%s&state=%s&scope=%s",
		Config.FbAppId,
		FbApp.RedirectUri,
		state,
		"manage_pages,publish_pages",
	), nil
}
