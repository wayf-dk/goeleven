package main

import (
	"github.com/wayf-dk/goeleven"
	x.config"
)

func main() {
    config.GoElevenPHPH.SlotPassword = config.Env("SlotPassword", "")
	goeleven.Init(config.GoElevenPHPH)
}
