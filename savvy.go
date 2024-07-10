package main

import (
	"github.com/raylax/savvy/log"
	"github.com/raylax/savvy/rule"
	"github.com/raylax/savvy/runner"
)

func main() {
	log.Root.Info("Starting...")
	err := rule.LoadRules("config/rules")
	if err != nil {
		log.Root.Error("Error loading rules", "error", err)
		return
	}
	err = rule.LoadServicePorts("config/service-ports.txt")
	if err != nil {
		log.Root.Error("Error loading service ports", "error", err)
		return
	}

	r := runner.NewRunner()
	r.Run()

}
