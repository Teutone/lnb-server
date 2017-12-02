#!/bin/bash

go build -o ./dist/lnb-server *.go



&& ./lnb-server data/config.json