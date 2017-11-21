package main

import (
	fb "github.com/huandu/facebook"
)

var FbApp *fb.App

func initFb() {
	FbApp = fb.New(Config.FbAppId, Config.FbAppSecret)
	FbApp.RedirectUri = "https://" + Config.Sites[0].Hostname + "/"
}
