#!/bin/bash

# build latenight.blue
cd ../lnb-client && npm run build
cp -r ../lnb-client/dist ./static/latenight.blue

# build eleventhirty.am
cd ../lnb-client && npm run build
cp -r ../etam-client/dist ./static/eleventhirty.am

CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ./main *.go
docker build -t b12f/lnb-server .
