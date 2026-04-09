package main

import (
	"log"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoldyzdk/sniff/internal/app"
	"github.com/zoldyzdk/sniff/internal/discovery"
)

func main() {
	model := app.NewModel(app.Config{
		Scanner:   discovery.NewProcScanner("/proc"),
		TickEvery: 2 * time.Second,
	})

	program := tea.NewProgram(model)
	if err := program.Start(); err != nil {
		log.Fatalf("sniff: %v", err)
	}
}
