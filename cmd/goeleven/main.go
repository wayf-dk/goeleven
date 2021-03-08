package main

import (
	"github.com/wayf-dk/goeleven"
	config "wayf.dk/hybrid-config"
)

func main() {
    config.GoElevenPHPH.SlotPassword = config.Env("SlotPassword", "")
	goeleven.Init(config.GoElevenPHPH)
}
