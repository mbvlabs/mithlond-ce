package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	focusedStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cursorStyle          = focusedStyle
	noStyle              = lipgloss.NewStyle()
	helpStyle            = blurredStyle
	cursorModeHelpStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	errorStyle           = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	formHeaderStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true)
	formInstructionStyle = helpStyle
	labelStyle           = helpStyle.Bold(true)
	labelFocusedStyle    = focusedStyle.Bold(true)
	labelErrorStyle      = errorStyle.Bold(true)
	inputBoxStyle        = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("238")).
				Padding(0, 1)
	inputBoxFocusedStyle = inputBoxStyle.BorderForeground(lipgloss.Color("205"))
	inputBoxErrorStyle   = inputBoxStyle.BorderForeground(lipgloss.Color("196"))

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
	CloudflareEmail  string `validate:"omitempty,email"`
	CloudflareAPIKey string
	SSHPort          string `validate:"required,ssh_port"`
	VPSIPv4          string `validate:"omitempty,ipv4"`
	VPSIPv6          string `validate:"omitempty,ipv6"`
	Domain           string `validate:"required,root_domain"`
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
	stage                stage
	form                 formData
	formError            string
	invalidInputIndex    int
	inputs               []textinput.Model
	focusIndex           int
	cursorMode           cursor.Mode
	loadingSpinner       spinner.Model
	secretInputHidden    map[int]bool
	ipv4                 string
	ipv6                 string
	confirmIndex         int
	completeIndex        int
	provisioning         bool
	provisioningStarted  bool
	provisioningComplete bool
	provisionErr         error
	provisionResult      provisioningResult
	rebooting            bool
	rebootErr            error
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	ctx := context.Background()

	switch msg := msg.(type) {
	case provisioningDoneMsg:
		m.provisioning = false
		m.provisioningComplete = true
		m.provisionErr = msg.err
		if msg.err == nil {
			m.provisionResult = msg.result
		}
		buttons := m.completeButtons()
		if len(buttons) == 0 {
			m.completeIndex = 0
		} else if m.completeIndex >= len(buttons) {
			m.completeIndex = 0
		}
		return m, nil
	case rebootDoneMsg:
		m.rebooting = false
		m.rebootErr = msg.err
		if msg.err == nil {
			return m, tea.Quit
		}
		return m, nil
	}

	switch m.stage {
	case formStage:
		return m.handleFormUpdate(msg)
	case confirmStage:
		return m.handleConfirmUpdate(ctx, msg)
	case completeStage:
		return m.handleCompleteUpdate(ctx, msg)
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

func (m *model) ensureSecretVisibility(index int) {
	if index < 0 || index >= len(m.inputs) {
		return
	}

	if m.secretInputHidden == nil {
		return
	}

	hidden, ok := m.secretInputHidden[index]
	if !ok {
		return
	}

	if hidden {
		m.inputs[index].EchoMode = textinput.EchoPassword
		m.inputs[index].EchoCharacter = '*'
		return
	}

	m.inputs[index].EchoMode = textinput.EchoNormal
}

func (m *model) toggleSecretVisibility(index int) {
	if m.secretInputHidden == nil {
		return
	}
	if _, ok := m.secretInputHidden[index]; !ok {
		return
	}
	m.secretInputHidden[index] = !m.secretInputHidden[index]
	m.ensureSecretVisibility(index)
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

func (m model) provisioningCmd(ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		result, err := runProvisioning(ctx, m.form, m.ipv4, m.ipv6)
		return provisioningDoneMsg{result: result, err: err}
	}
}

func (m model) rebootCmd(ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		err := rebootHost(ctx)
		return rebootDoneMsg{err: err}
	}
}

func (m model) formView() string {
	var b strings.Builder

	b.WriteString(formHeaderStyle.Render("Step 1 of 3 - Configure server and DNS"))
	b.WriteString("\n")
	b.WriteString(
		formInstructionStyle.Render(
			"Tab/Shift+Tab move | Enter submits | Esc cancels | Ctrl+V toggle secrets",
		),
	)
	b.WriteString("\n")

	if strings.TrimSpace(m.formError) != "" {
		b.WriteString("\n")
		b.WriteString(errorStyle.Render(m.formError))
		b.WriteString("\n")
	}

	for i := range m.inputs {
		if i > 0 {
			b.WriteString("\n")
		}

		label := strings.TrimSpace(m.inputs[i].Placeholder)
		if label == "" {
			label = "Field"
		}

		labelRender := labelStyle
		boxRender := inputBoxStyle

		if m.secretInputHidden != nil {
			if hidden, ok := m.secretInputHidden[i]; ok {
				if hidden {
					label += " (hidden)"
				} else {
					label += " (visible)"
				}
			}
		}

		switch i {
		case m.invalidInputIndex:
			labelRender = labelErrorStyle
			boxRender = inputBoxErrorStyle
		case m.focusIndex:
			labelRender = labelFocusedStyle
			boxRender = inputBoxFocusedStyle
		}

		b.WriteString(labelRender.Render(label))
		b.WriteString("\n")
		b.WriteString(boxRender.Render(m.inputs[i].View()))
		b.WriteString("\n")
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

type provisioningDoneMsg struct {
	result provisioningResult
	err    error
}

type rebootDoneMsg struct {
	err error
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
	detected := strings.TrimSpace(m.ipv4)

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
	detected := strings.TrimSpace(m.ipv6)

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
		lines = append(lines, fmt.Sprintf("- %s.%s", prefix, rootDomain))
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
	b.WriteString(formHeaderStyle.Render("Step 2 of 3 - Review configuration"))
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
	var b strings.Builder

	switch {
	case m.provisioning:
		b.WriteString(formHeaderStyle.Render("Step 3 of 3 - Provisioning"))
		b.WriteString("\n")
		b.WriteString(
			focusedStyle.Render(
				fmt.Sprintf("%s Provisioning in progress", m.loadingSpinner.View()),
			),
		)
		b.WriteString("\n")
		b.WriteString(
			helpStyle.Render(
				"Running install scripts and provisioning resources. This may take a few minutes.",
			),
		)
		b.WriteString("\n")
		b.WriteString(
			helpStyle.Render("Keep this window open; we'll advance once everything is ready."),
		)
		return b.String()
	case m.provisionErr != nil:
		b.WriteString(formHeaderStyle.Render("Step 3 of 3 - Provisioning"))
		b.WriteString("\n")
		b.WriteString(focusedStyle.Render("Provisioning Failed"))
		b.WriteString("\n\n")
		b.WriteString(m.provisionErr.Error())
		b.WriteString("\n\n")
		b.WriteString(
			helpStyle.Render("Fix the issue and restart the installer or press Exit to quit."),
		)
		b.WriteString("\n\n")
		b.WriteString(m.renderCompleteButtons())
		return b.String()
	default:
		b.WriteString(formHeaderStyle.Render("Step 3 of 3 - Provisioning"))
		b.WriteString("\n")
		b.WriteString(focusedStyle.Render("Provisioning Complete"))
		b.WriteString("\n")
		b.WriteString(
			helpStyle.Render(
				"Copy these credentials now. They will not be shown again after reboot.",
			),
		)
		b.WriteString("\n\n")

		rows := m.completeSummaryRows()
		maxLabel := 0
		for _, row := range rows {
			if len(row.label) > maxLabel {
				maxLabel = len(row.label)
			}
		}

		labelWidth := maxLabel + 2
		for _, row := range rows {
			label := fmt.Sprintf("%s:", row.label)
			lines := strings.Split(row.value, "\n")
			fmt.Fprintf(&b, "%-*s %s\n", labelWidth, label, lines[0])
			for _, line := range lines[1:] {
				fmt.Fprintf(&b, "%-*s %s\n", labelWidth, "", line)
			}
		}

		if m.rebootErr != nil {
			b.WriteString("\n")
			b.WriteString(focusedStyle.Render("Reboot Failed"))
			b.WriteString("\n")
			b.WriteString(m.rebootErr.Error())
			b.WriteString("\n")
		}

		if m.rebooting {
			b.WriteString("\n")
			b.WriteString(helpStyle.Render("Reboot command sent; waiting for completion..."))
			b.WriteString("\n")
		}

		b.WriteString("\n")
		b.WriteString(
			helpStyle.Render(
				"Use your terminal's copy shortcut (e.g. Shift+Ctrl+C) to capture these details before rebooting.",
			),
		)
		b.WriteString("\n")
		b.WriteString(
			helpStyle.Render("When you are done, select Reboot to finish applying the changes."),
		)
		b.WriteString("\n\n")
		b.WriteString(m.renderCompleteButtons())
		return b.String()
	}
}

func (m model) completeSummaryRows() []summaryRow {
	rows := []summaryRow{
		{label: "SSH Username", value: formatOrPlaceholder(m.form.Username)},
		{label: "SSH Password", value: formatOrPlaceholder(m.form.Password)},
		{label: "SSH Port", value: formatOrPlaceholder(m.form.SSHPort)},
		{label: "Cloudflare Email", value: formatOrPlaceholder(m.form.CloudflareEmail)},
		{label: "Cloudflare API Key", value: formatOrPlaceholder(m.form.CloudflareAPIKey)},
		{
			label: "Caddy Username",
			value: formatOrPlaceholder(m.provisionResult.envVars["CADDY_USER_NAME"]),
		},
		{label: "Caddy Password", value: formatOrPlaceholder(m.provisionResult.caddyPassword)},
		{label: "IPv4", value: m.ipv4Summary()},
		{label: "IPv6", value: m.ipv6Summary()},
		{label: "Root Domain", value: formatOrPlaceholder(m.form.Domain)},
		{label: "Basic Auth Username", value: formatOrPlaceholder(m.provisionResult.caddyUsername)},
		{label: "Basic Auth password", value: formatOrPlaceholder(m.provisionResult.caddyPassword)},
	}

	if len(m.provisionResult.hostnames) > 0 {
		formatted := make([]string, 0, len(m.provisionResult.hostnames))
		for _, host := range m.provisionResult.hostnames {
			formatted = append(formatted, "- "+host)
		}
		rows = append(rows, summaryRow{label: "Hostnames", value: strings.Join(formatted, "\n")})
	} else {
		rows = append(rows, summaryRow{label: "Hostnames", value: "(no hostnames configured)"})
	}

	return rows
}

func (m model) renderCompleteButtons() string {
	if m.provisioning {
		return ""
	}

	buttons := m.completeButtons()
	var b strings.Builder
	for i, label := range buttons {
		if i > 0 {
			b.WriteString("  ")
		}
		if i == m.completeIndex {
			b.WriteString(focusedStyle.Render(fmt.Sprintf("[ %s ]", label)))
			continue
		}
		b.WriteString(fmt.Sprintf("[ %s ]", blurredStyle.Render(label)))
	}
	return b.String()
}

func (m model) completeButtons() []string {
	if m.provisionErr != nil {
		return []string{"Exit"}
	}
	return []string{"Reboot", "Exit"}
}

func (m model) handleFormUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "ctrl+v":
			if m.focusIndex >= 0 && m.focusIndex < len(m.inputs) {
				m.toggleSecretVisibility(m.focusIndex)
			}
			return m, nil

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
				m.syncFormDataInline()
				sanitized, validationErr := validateAndNormalizeFormData(m.form)
				if validationErr != nil {
					m.formError = validationErr.message
					m.invalidInputIndex = validationErr.inputIndex
					if validationErr.inputIndex >= 0 && validationErr.inputIndex < len(m.inputs) {
						cmd := m.setFocus(validationErr.inputIndex)
						return m, cmd
					}
					return m, nil
				}

				m.formError = ""
				m.invalidInputIndex = -1
				m.applyFormData(sanitized)
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
	m.enforceSSHPortDigits()

	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.Type {
		case tea.KeyRunes, tea.KeyBackspace, tea.KeyDelete, tea.KeySpace:
			m.formError = ""
			m.invalidInputIndex = -1
		}
	}

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

func (m *model) enforceSSHPortDigits() {
	if len(m.inputs) <= inputSSHPort {
		return
	}

	current := m.inputs[inputSSHPort].Value()
	filtered := digitsOnly(current)
	if current == filtered {
		return
	}

	m.inputs[inputSSHPort].SetValue(filtered)
}

func (m *model) applyFormData(data formData) {
	m.form = data

	if len(m.inputs) > inputUsername {
		m.inputs[inputUsername].SetValue(data.Username)
	}
	if len(m.inputs) > inputPassword {
		m.inputs[inputPassword].SetValue(data.Password)
		m.ensureSecretVisibility(inputPassword)
	}
	if len(m.inputs) > inputCloudflareEmail {
		m.inputs[inputCloudflareEmail].SetValue(data.CloudflareEmail)
	}
	if len(m.inputs) > inputCloudflareAPIKey {
		m.inputs[inputCloudflareAPIKey].SetValue(data.CloudflareAPIKey)
		m.ensureSecretVisibility(inputCloudflareAPIKey)
	}
	if len(m.inputs) > inputSSHPort {
		m.inputs[inputSSHPort].SetValue(data.SSHPort)
	}
	if len(m.inputs) > inputVPSIPv4 {
		m.inputs[inputVPSIPv4].SetValue(data.VPSIPv4)
	}
	if len(m.inputs) > inputVPSIPv6 {
		m.inputs[inputVPSIPv6].SetValue(data.VPSIPv6)
	}
	if len(m.inputs) > inputDomain {
		m.inputs[inputDomain].SetValue(data.Domain)
	}
}

func digitsOnly(s string) string {
	if s == "" {
		return s
	}

	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (m model) handleConfirmUpdate(ctx context.Context, msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			m.stage = formStage
			m.invalidInputIndex = -1
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
				if m.provisioning {
					return m, nil
				}
				m.provisioning = true
				m.provisioningStarted = true
				m.provisioningComplete = false
				m.provisionErr = nil
				m.stage = completeStage
				m.completeIndex = 0
				return m, tea.Batch(m.provisioningCmd(ctx), m.loadingSpinner.Tick)
			}

			m.stage = formStage
			cmd := m.setFocus(0)
			return m, cmd
		}
	}

	return m, nil
}

func (m model) handleCompleteUpdate(ctx context.Context, msg tea.Msg) (tea.Model, tea.Cmd) {
	cmds := make([]tea.Cmd, 0, 2)
	if m.provisioning {
		var spinCmd tea.Cmd
		m.loadingSpinner, spinCmd = m.loadingSpinner.Update(msg)
		if spinCmd != nil {
			cmds = append(cmds, spinCmd)
		}
		if _, ok := msg.(spinner.TickMsg); ok {
			if len(cmds) == 0 {
				return m, nil
			}
			return m, tea.Batch(cmds...)
		}
	}

	withPending := func(next tea.Cmd) (tea.Model, tea.Cmd) {
		if next != nil {
			cmds = append(cmds, next)
		}
		if len(cmds) == 0 {
			return m, nil
		}
		return m, tea.Batch(cmds...)
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "tab", "shift+tab", "left", "right":
			if m.provisioning || m.rebooting {
				return withPending(nil)
			}
			buttons := m.completeButtons()
			if len(buttons) == 0 {
				return withPending(nil)
			}

			if msg.String() == "left" || msg.String() == "shift+tab" {
				m.completeIndex--
			} else {
				m.completeIndex++
			}

			if m.completeIndex < 0 {
				m.completeIndex = len(buttons) - 1
			}
			if m.completeIndex >= len(buttons) {
				m.completeIndex = 0
			}

			return withPending(nil)
		case "enter":
			if m.provisioning || m.rebooting {
				return withPending(nil)
			}

			buttons := m.completeButtons()
			if len(buttons) == 0 {
				return withPending(nil)
			}

			if m.completeIndex >= len(buttons) {
				m.completeIndex = 0
			}

			switch buttons[m.completeIndex] {
			case "Reboot":
				m.rebooting = true
				m.rebootErr = nil
				return withPending(m.rebootCmd(ctx))
			case "Exit":
				return m, tea.Quit
			}
		}
	}

	return withPending(nil)
}

func (m *model) setFocus(index int) tea.Cmd {
	m.focusIndex = index
	cmds := make([]tea.Cmd, 0, len(m.inputs))
	for i := range m.inputs {
		if index >= 0 && index < len(m.inputs) && i == index {
			cmd := m.inputs[i].Focus()
			m.inputs[i].PromptStyle = focusedStyle
			m.inputs[i].TextStyle = focusedStyle
			m.ensureSecretVisibility(i)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
			continue
		}

		m.inputs[i].Blur()
		m.inputs[i].PromptStyle = noStyle
		m.inputs[i].TextStyle = noStyle
		m.ensureSecretVisibility(i)
	}

	if len(cmds) == 0 {
		return nil
	}

	return tea.Batch(cmds...)
}
