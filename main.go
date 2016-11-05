package main

import (
	"fmt"
	"log"
	"os"

	"github.com/coreos/go-semver/semver"
	"github.com/royvandewater/meshchain/httpserver"
	"github.com/urfave/cli"
	De "github.com/visionmedia/go-debug"
)

var debug = De.Debug("meshchain:main")

func main() {
	app := cli.NewApp()
	app.Name = "meshchain"
	app.Version = version()
	app.Action = run
	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:   "port, p",
			EnvVar: "MESHCHAIN_PORT",
			Usage:  "`PORT` on which to listen",
			Value:  80,
		},
	}
	app.Run(os.Args)
}

func run(context *cli.Context) {
	port := getOpts(context)

	log.Printf("Listening on: %v", port)
	server := httpserver.New(port)
	err := server.Run()
	if err != nil {
		log.Fatalln(err.Error())
	}
	os.Exit(0)
}

func getOpts(context *cli.Context) int {
	port := context.Int("port")
	return port
}

func version() string {
	version, err := semver.NewVersion(VERSION)
	if err != nil {
		errorMessage := fmt.Sprintf("Error with version number: %v", VERSION)
		log.Panicln(errorMessage, err.Error())
	}
	return version.String()
}
