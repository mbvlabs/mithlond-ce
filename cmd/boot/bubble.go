package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	focusedStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cursorStyle         = focusedStyle
	noStyle             = lipgloss.NewStyle()
	helpStyle           = blurredStyle
	cursorModeHelpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	focusedButton = focusedStyle.Render("[ Submit ]")
	blurredButton = fmt.Sprintf("[ %s ]", blurredStyle.Render("Submit"))

	domainPrefix = map[string]string{
		"MITHLOND_DOMAIN_NAME":  "test-mithlond",
		"TEL_PROM_DOMAIN_NAME":  "test-telemetry-prometheus",
		"TEL_LOKI_DOMAIN_NAME":  "test-telemetry-loki",
		"TEL_TEMPO_DOMAIN_NAME": "test-telemetry-tempo",
		"TEL_ALLOY_DOMAIN_NAME": "test-telemetry-alloy",
	}
)

var domainPrefixOrder = []string{
	"MITHLOND_DOMAIN_NAME",
	"TEL_PROM_DOMAIN_NAME",
	"TEL_LOKI_DOMAIN_NAME",
	"TEL_TEMPO_DOMAIN_NAME",
	"TEL_ALLOY_DOMAIN_NAME",
}

type stage int

const (
	formStage stage = iota
	confirmStage
	completeStage
)

type formData struct {
	Username         string
	Password         string
	CloudflareEmail  string
	CloudflareAPIKey string
	SSHPort          string
	VPSIPv4          string
	VPSIPv6          string
	Domain           string
}

const (
	inputUsername = iota
	inputPassword
	inputCloudflareEmail
	inputCloudflareAPIKey
	inputSSHPort
	inputVPSIPv4
	inputVPSIPv6
	inputDomain
	totalInputs
)

const (
	confirmApprove = iota
	confirmBack
	totalConfirmActions
)

type model struct {
	stage        stage
	form         formData
	inputs       []textinput.Model
	focusIndex   int
	cursorMode   cursor.Mode
	detectedIPv4 string
	detectedIPv6 string
	confirmIndex int
	confirmed    bool
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.stage {
	case formStage:
		return m.handleFormUpdate(msg)
	case confirmStage:
		return m.handleConfirmUpdate(msg)
	case completeStage:
		return m.handleCompleteUpdate(msg)
	default:
		return m, nil
	}
}

func (m *model) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))
	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}
	return tea.Batch(cmds...)
}

func (m model) View() string {
	switch m.stage {
	case formStage:
		return m.formView()
	case confirmStage:
		return m.confirmView()
	case completeStage:
		return m.completeView()
	default:
		return ""
	}
}

func (m model) formView() string {
	var b strings.Builder

	for i := range m.inputs {
		fmt.Fprintf(&b, "\n%s \n%s", helpStyle.Render(m.inputs[i].Placeholder), m.inputs[i].View())
		if i < len(m.inputs)-1 {
			b.WriteRune('\n')
		}
	}

	button := &blurredButton
	if m.focusIndex == len(m.inputs) {
		button = &focusedButton
	}

	fmt.Fprintf(&b, "\n\n%s\n\n", *button)

	b.WriteString(helpStyle.Render("cursor mode is "))
	b.WriteString(cursorModeHelpStyle.Render(m.cursorMode.String()))
	b.WriteString(helpStyle.Render(" (ctrl+r to change style)"))

	return b.String()
}

type summaryRow struct {
	label string
	value string
}

func (m model) confirmSummaryRows() []summaryRow {
	rows := []summaryRow{
		{label: "Username", value: formatOrPlaceholder(m.form.Username)},
		{label: "Password", value: formatOrPlaceholder(m.form.Password)},
		{label: "Cloudflare Email", value: formatOrPlaceholder(m.form.CloudflareEmail)},
		{label: "Cloudflare API Key", value: formatOrPlaceholder(m.form.CloudflareAPIKey)},
		{label: "SSH Port", value: formatOrPlaceholder(m.form.SSHPort)},
		{label: "IPv4", value: m.ipv4Summary()},
		{label: "IPv6", value: m.ipv6Summary()},
		{label: "Root Domain", value: formatOrPlaceholder(m.form.Domain)},
	}

	rows = append(rows, summaryRow{label: "Hostnames", value: m.hostnamesSummary()})

	return rows
}

func formatOrPlaceholder(value string) string {
	if strings.TrimSpace(value) == "" {
		return "(not provided)"
	}
	return value
}

func (m model) ipv4Summary() string {
	override := strings.TrimSpace(m.form.VPSIPv4)
	detected := strings.TrimSpace(m.detectedIPv4)

	switch {
	case override != "" && detected != "" && override != detected:
		return fmt.Sprintf("%s (manual override, detected %s)", override, detected)
	case override != "" && detected != "":
		return fmt.Sprintf("%s (auto-detected)", detected)
	case override != "":
		return fmt.Sprintf("%s (manual override)", override)
	case detected != "":
		return fmt.Sprintf("%s (auto-detected)", detected)
	default:
		return "(not provided)"
	}
}

func (m model) ipv6Summary() string {
	override := strings.TrimSpace(m.form.VPSIPv6)
	detected := strings.TrimSpace(m.detectedIPv6)

	switch {
	case override != "" && detected != "" && override != detected:
		return fmt.Sprintf("%s (manual override, detected %s)", override, detected)
	case override != "" && detected != "":
		return fmt.Sprintf("%s (auto-detected)", detected)
	case override != "":
		return fmt.Sprintf("%s (manual override)", override)
	case detected != "":
		return fmt.Sprintf("%s (auto-detected)", detected)
	default:
		return "(not provided)"
	}
}

func (m model) hostnamesSummary() string {
	rootDomain := strings.TrimSpace(m.form.Domain)
	if rootDomain == "" {
		return "(domain not provided)"
	}

	lines := make([]string, 0, len(domainPrefixOrder))
	for _, envName := range domainPrefixOrder {
		prefix, ok := domainPrefix[envName]
		if !ok {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s.%s", prefix, rootDomain))
	}

	if len(lines) == 0 {
		return "(no hostnames configured)"
	}

	return strings.Join(lines, "\n")
}

func (m model) confirmView() string {
	rows := m.confirmSummaryRows()
	maxLabel := 0
	for _, row := range rows {
		if len(row.label) > maxLabel {
			maxLabel = len(row.label)
		}
	}

	var b strings.Builder
	b.WriteString(focusedStyle.Render("Review Configuration"))
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("Ensure these values are correct before provisioning."))
	b.WriteString("\n\n")

	labelWidth := maxLabel + 2
	for _, row := range rows {
		label := fmt.Sprintf("%s:", row.label)
		lines := strings.Split(row.value, "\n")
		fmt.Fprintf(&b, "%-*s %s\n", labelWidth, label, lines[0])
		for _, line := range lines[1:] {
			fmt.Fprintf(&b, "%-*s %s\n", labelWidth, "", line)
		}
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("Use tab/arrow keys to switch buttons; press enter to select."))
	b.WriteString("\n\n")

	buttons := []string{"Approve", "Back"}
	for i, label := range buttons {
		if i > 0 {
			b.WriteString("  ")
		}
		if i == m.confirmIndex {
			b.WriteString(focusedStyle.Render(fmt.Sprintf("[ %s ]", label)))
			continue
		}
		b.WriteString(fmt.Sprintf("[ %s ]", blurredStyle.Render(label)))
	}

	b.WriteString("\n")
	return b.String()
}

func (m model) completeView() string {
	return helpStyle.Render("complete view not yet implemented")
}

// func (m *model) handleFormUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
//     defer m.syncFormData()
//     // ... rest of method
// }

func (m model) handleFormUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit

		case "ctrl+r":
			m.cursorMode++
			if m.cursorMode > cursor.CursorHide {
				m.cursorMode = cursor.CursorBlink
			}
			cmds := make([]tea.Cmd, len(m.inputs))
			for i := range m.inputs {
				cmds[i] = m.inputs[i].Cursor.SetMode(m.cursorMode)
			}
			return m, tea.Batch(cmds...)

		case "tab", "shift+tab", "enter", "up", "down":
			s := msg.String()

			if s == "enter" && m.focusIndex == len(m.inputs) {
				// Sync form data before changing stage
				m.syncFormDataInline()
				m.stage = confirmStage
				m.confirmIndex = confirmApprove
				m.setFocus(len(m.inputs))
				return m, nil
			}

			if s == "up" || s == "shift+tab" {
				m.focusIndex--
			} else {
				m.focusIndex++
			}

			if m.focusIndex > len(m.inputs) {
				m.focusIndex = 0
			} else if m.focusIndex < 0 {
				m.focusIndex = len(m.inputs)
			}

			if m.focusIndex < len(m.inputs) {
				cmd := m.setFocus(m.focusIndex)
				return m, cmd
			}

			m.setFocus(len(m.inputs))
			return m, nil
		}
	}

	cmd := m.updateInputs(msg)
	// Sync form data after updating inputs
	m.syncFormDataInline()
	return m, cmd
}

func (m *model) syncFormDataInline() {
	if len(m.inputs) == 0 {
		return
	}

	if len(m.inputs) > inputUsername {
		m.form.Username = m.inputs[inputUsername].Value()
	}
	if len(m.inputs) > inputPassword {
		m.form.Password = m.inputs[inputPassword].Value()
	}
	if len(m.inputs) > inputCloudflareEmail {
		m.form.CloudflareEmail = m.inputs[inputCloudflareEmail].Value()
	}
	if len(m.inputs) > inputCloudflareAPIKey {
		m.form.CloudflareAPIKey = m.inputs[inputCloudflareAPIKey].Value()
	}
	if len(m.inputs) > inputSSHPort {
		m.form.SSHPort = m.inputs[inputSSHPort].Value()
	}
	if len(m.inputs) > inputVPSIPv4 {
		m.form.VPSIPv4 = m.inputs[inputVPSIPv4].Value()
	}
	if len(m.inputs) > inputVPSIPv6 {
		m.form.VPSIPv6 = m.inputs[inputVPSIPv6].Value()
	}
	if len(m.inputs) > inputDomain {
		m.form.Domain = m.inputs[inputDomain].Value()
	}
}

// func (m model) handleFormUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
// 	defer m.syncFormData()
//
// 	switch msg := msg.(type) {
// 	case tea.KeyMsg:
// 		switch msg.String() {
// 		case "ctrl+c", "esc":
// 			return m, tea.Quit
//
// 		case "ctrl+r":
// 			m.cursorMode++
// 			if m.cursorMode > cursor.CursorHide {
// 				m.cursorMode = cursor.CursorBlink
// 			}
// 			cmds := make([]tea.Cmd, len(m.inputs))
// 			for i := range m.inputs {
// 				cmds[i] = m.inputs[i].Cursor.SetMode(m.cursorMode)
// 			}
// 			return m, tea.Batch(cmds...)
//
// 		case "tab", "shift+tab", "enter", "up", "down":
// 			s := msg.String()
//
// 			if s == "enter" && m.focusIndex == len(m.inputs) {
// 				m.stage = confirmStage
// 				m.confirmIndex = confirmApprove
// 				m.setFocus(len(m.inputs))
// 				return m, nil
// 			}
//
// 			if s == "up" || s == "shift+tab" {
// 				m.focusIndex--
// 			} else {
// 				m.focusIndex++
// 			}
//
// 			if m.focusIndex > len(m.inputs) {
// 				m.focusIndex = 0
// 			} else if m.focusIndex < 0 {
// 				m.focusIndex = len(m.inputs)
// 			}
//
// 			if m.focusIndex < len(m.inputs) {
// 				cmd := m.setFocus(m.focusIndex)
// 				return m, cmd
// 			}
//
// 			m.setFocus(len(m.inputs))
// 			return m, nil
// 		}
// 	}
//
// 	return m, m.updateInputs(msg)
// }

func (m model) handleConfirmUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			m.stage = formStage
			cmd := m.setFocus(0)
			return m, cmd
		case "tab", "shift+tab", "left", "right":
			if msg.String() == "left" || msg.String() == "shift+tab" {
				m.confirmIndex--
			} else {
				m.confirmIndex++
			}

			if m.confirmIndex >= totalConfirmActions {
				m.confirmIndex = 0
			} else if m.confirmIndex < 0 {
				m.confirmIndex = totalConfirmActions - 1
			}

			return m, nil
		case "enter":
			if m.confirmIndex == confirmApprove {
				m.confirmed = true
				return m, tea.Quit
			}

			m.stage = formStage
			cmd := m.setFocus(0)
			return m, cmd
		}
	}

	return m, nil
}

func (m model) handleCompleteUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m *model) syncFormData() {
	if len(m.inputs) == 0 {
		return
	}

	if len(m.inputs) > inputUsername {
		m.form.Username = m.inputs[inputUsername].Value()
	}
	if len(m.inputs) > inputPassword {
		m.form.Password = m.inputs[inputPassword].Value()
	}
	if len(m.inputs) > inputCloudflareEmail {
		m.form.CloudflareEmail = m.inputs[inputCloudflareEmail].Value()
	}
	if len(m.inputs) > inputCloudflareAPIKey {
		m.form.CloudflareAPIKey = m.inputs[inputCloudflareAPIKey].Value()
	}
	if len(m.inputs) > inputSSHPort {
		m.form.SSHPort = m.inputs[inputSSHPort].Value()
	}
	if len(m.inputs) > inputVPSIPv4 {
		m.form.VPSIPv4 = m.inputs[inputVPSIPv4].Value()
	}
	if len(m.inputs) > inputVPSIPv6 {
		m.form.VPSIPv6 = m.inputs[inputVPSIPv6].Value()
	}
	if len(m.inputs) > inputDomain {
		m.form.Domain = m.inputs[inputDomain].Value()
	}
}

func (m *model) setFocus(index int) tea.Cmd {
	m.focusIndex = index
	cmds := make([]tea.Cmd, 0, len(m.inputs))
	for i := range m.inputs {
		if index >= 0 && index < len(m.inputs) && i == index {
			cmd := m.inputs[i].Focus()
			m.inputs[i].PromptStyle = focusedStyle
			m.inputs[i].TextStyle = focusedStyle
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
			continue
		}

		m.inputs[i].Blur()
		m.inputs[i].PromptStyle = noStyle
		m.inputs[i].TextStyle = noStyle
	}

	if len(cmds) == 0 {
		return nil
	}

	return tea.Batch(cmds...)
}
