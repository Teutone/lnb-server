package main

import (
	"log"
	"os"
)

func main() {
	configFile := os.Args[1]

	if len(configFile) == 0 {
		log.Fatal("Please specify the config file location as the first cli argument")
	}

	InitConfig(configFile)
	InitDatabase()
	Serve()
}
