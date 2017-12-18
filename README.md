# lnb-server

| **lnb-server**
| [latenight.blue client](https://github.com/b12f/lnb-client)
| [eleventhirty.am client](https://github.com/b12f/etam-client)
|

This is the server-side application for [latenight.blue](https://latenight.blue/) and [eleventhirty.am](https://eleventhirty.am/).

## Production setup

The current production setup consists of a Docker daemon with an nginx proxy server that has automatic letsencrypt enabled. Check out [JrCs/docker-letsencrypt-nginx-proxy-companion](https://github.com/JrCs/docker-letsencrypt-nginx-proxy-companion) for more information on how to run an application in a similar environment.

## Features

* Multiple vhosts
* REST-like API
* Multiple logins
* Automatic facebook posting
* No Database needed, all data is written to JSON files

## Building

### Local build

    go build ./main *.go

### Drone / Docker build

Make sure you have a Drone server running somewhere, and edit `.drone.yml` to fit your needs.

## Starting

The binary takes only one argument: the config file location.

## Config

Check out `config/config.example.json` for an example.