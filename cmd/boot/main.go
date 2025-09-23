package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/dns"
	"github.com/cloudflare/cloudflare-go/v6/option"
	"github.com/cloudflare/cloudflare-go/v6/zones"
	"github.com/mbvlabs/mithlond-ce/scripts"
	"golang.org/x/crypto/bcrypt"
)

var releaseVersion string

const (
	charset        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	passwordLength = 8
)

func randomString(length int) string {
	result := make([]byte, length)
	for i := range length {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[idx.Int64()]
	}
	return string(result)
}

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

type model struct {
	inputs     []textinput.Model
	focusIndex int
	cursorMode cursor.Mode
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit

		// Change cursor mode
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
				return m, tea.Quit
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

			cmds := make([]tea.Cmd, len(m.inputs))
			for i := 0; i <= len(m.inputs)-1; i++ {
				if i == m.focusIndex {
					// Set focused state
					cmds[i] = m.inputs[i].Focus()
					m.inputs[i].PromptStyle = focusedStyle
					m.inputs[i].TextStyle = focusedStyle
					continue
				}
				// Remove focused state
				m.inputs[i].Blur()
				m.inputs[i].PromptStyle = noStyle
				m.inputs[i].TextStyle = noStyle
			}

			return m, tea.Batch(cmds...)
		}
	}

	cmd := m.updateInputs(msg)

	return m, cmd
}

func (m *model) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))

	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}

	return tea.Batch(cmds...)
}

func (m model) View() string {
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

func main() {
	ctx := context.Background()

	m := model{
		inputs: make([]textinput.Model, 8),
	}

	var t textinput.Model
	for i := range m.inputs {
		t = textinput.New()
		t.Cursor.Style = cursorStyle
		t.CharLimit = 150

		switch i {
		case 0:
			t.Placeholder = "Enter Username for ssh access"
			t.Focus()
			t.PromptStyle = focusedStyle
			t.TextStyle = focusedStyle
		case 1:
			t.Placeholder = "Enter Password for ssh access"
			// t.EchoMode = textinput.EchoPassword
			// t.EchoCharacter = '•'
		case 2:
			t.Placeholder = "Confirm Password for ssh access"
			// t.EchoMode = textinput.EchoPassword
			// t.EchoCharacter = '•'
		case 3:
			t.Placeholder = "Enter Cloudflare email"
		case 4:
			t.Placeholder = "Enter Cloudflare API key"
			// t.EchoMode = textinput.EchoPassword
			// t.EchoCharacter = '•'
		// case 5:
		// 	t.Placeholder = "Enter AWS Access Key ID"
		// case 6:
		// 	t.Placeholder = "Enter AWS Secret Access Key"
		// 	t.EchoMode = textinput.EchoPassword
		// 	t.EchoCharacter = '•'
		case 5:
			t.Placeholder = "Enter SSH port (default 22)"
		case 6:
			t.Placeholder = "Enter VPS IPv4"
		case 7:
			t.Placeholder = "Enter domain name (e.g., example.com)"
		}

		m.inputs[i] = t
	}

	p := tea.NewProgram(m)
	inputs, err := p.Run()
	if err != nil {
		fmt.Printf("could not start program: %s\n", err)
		os.Exit(1)
	}

	finalModel := inputs.(model)

	var domains []string
	var rootDomain string

	envVars := make(map[string]string, 9)
	for _, input := range finalModel.inputs {
		fmt.Printf("%s: %s\n", input.Placeholder, input.Value())
		switch input.Placeholder {
		case "Enter Username for ssh access":
			envVars["USER_NAME"] = input.Value()
		case "Enter Password for ssh access":
			envVars["USER_PASSWORD"] = input.Value()
		// case "Enter Cloudflare email":
		// 	envvars["CF_EMAIL"] = input.Value()
		case "Enter Cloudflare API key":
			envVars["CF_API_KEY"] = input.Value()
		// case "Enter AWS Access Key ID":
		// 	envvars["AWS_ACCESS_KEY_ID"] = input.Value()
		// case "Enter AWS Secret Access Key":
		// 	envvars["AWS_SECRET_ACCESS_KEY"] = input.Value()
		case "Enter domain name (e.g., example.com)":
			rd := input.Value()
			rootDomain = rd

			for envName, prefix := range domainPrefix {
				fullDomain := prefix + "." + rootDomain

				envVars[envName] = fullDomain

				domains = append(domains, fullDomain)
			}

		case "Enter SSH port (default 22)":
			envVars["SSH_PORT"] = input.Value()
		case "Enter VPS IPv4":
			envVars["VPS_IP"] = input.Value()
		}
	}

	if releaseVersion != "" {
		envVars["LATEST_RELEASE"] = releaseVersion
	}
	if releaseVersion == "" {
		envVars["LATEST_RELEASE"] = "latest"
	}

	caddyPassword := randomString(passwordLength)
	hash, err := bcrypt.GenerateFromPassword([]byte(caddyPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	envVars["CADDY_USER_NAME"] = envVars["USER_NAME"]
	envVars["CADDY_PASSWORD"] = string(hash)

	for key, value := range envVars {
		os.Setenv(key, value)
	}

	bootScript, err := scripts.Scripts.ReadFile("boot.sh")
	if err != nil {
		log.Fatal("Failed to read embedded install script:", err)
	}

	tempScriptPath := "/tmp/mithlond-boot.sh"

	if err := os.WriteFile(tempScriptPath, bootScript, 0o755); err != nil {
		log.Fatal("Failed to create temporary install script:", err)
	}
	defer os.Remove(tempScriptPath)

	cmd := exec.CommandContext(ctx, "/bin/bash", tempScriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		log.Fatal("Installation failed:", err)
	}

	client := cloudflare.NewClient(
		option.WithAPIToken(
			envVars["CF_API_KEY"],
		),
	)

	res, err := client.Zones.List(ctx, zones.ZoneListParams{
		Name: cloudflare.F(rootDomain),
	})
	if err != nil {
		panic(err)
	}

	var zoneID string
	for _, z := range res.Result {
		if z.Name == rootDomain {
			zoneID = z.ID
		}
	}

	for _, domain := range domains {
		slog.Info("setting up dns records", "record", domain)

		_, err := client.DNS.Records.New(ctx, dns.RecordNewParams{
			ZoneID: cloudflare.F(zoneID),
			Body: dns.ARecordParam{
				Name:    cloudflare.F(domain),
				TTL:     cloudflare.F(dns.TTL1),
				Type:    cloudflare.F(dns.ARecordTypeA),
				Comment: cloudflare.F("added by mithlond - do not remove"),
				Content: cloudflare.F(envVars["VPS_IP"]),
				Proxied: cloudflare.F(true),
			},
		})
		if err != nil {
			panic(err)
		}
	}

	slog.Info(
		"vps is now configured. save the following",
		"caddy_username",
		envVars["CADDY_USER_NAME"],
		"caddy_password",
		caddyPassword,
	)

	rebootCmd := exec.Command("sudo", "reboot")
	if err := rebootCmd.Run(); err != nil {
		fmt.Println("Error:", err)
	}
}
