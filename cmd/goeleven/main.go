package main

import (
	"github.com/wayf-dk/goeleven"
	"x.config"
)

func main() {
	config.Init()
	goeleven.Init(config.GoElevenPHPH)
}
