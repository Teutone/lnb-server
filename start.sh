#!/bin/bash

go build -o lnb-server *.go && ./lnb-server data/config.json