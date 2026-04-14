package app

import "github.com/charmbracelet/lipgloss"

type theme struct {
	header       lipgloss.Style
	selectedRow  lipgloss.Style
	normalRow    lipgloss.Style
	detailsTitle lipgloss.Style
	warning      lipgloss.Style
	success      lipgloss.Style
	locked       lipgloss.Style
	footer       lipgloss.Style
	searchLabel  lipgloss.Style
}

func defaultTheme() theme {
	return theme{
		header:       lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")),
		selectedRow:  lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")),
		normalRow:    lipgloss.NewStyle().Foreground(lipgloss.Color("252")),
		detailsTitle: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("69")),
		warning:      lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true),
		success:      lipgloss.NewStyle().Foreground(lipgloss.Color("42")),
		locked:       lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true),
		footer:       lipgloss.NewStyle().Foreground(lipgloss.Color("244")),
		searchLabel:  lipgloss.NewStyle().Foreground(lipgloss.Color("111")).Bold(true),
	}
}
