package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
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

func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func getPublicIP(version string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "curl", version, "-s", "ifconfig.me")
	output, err := cmd.Output()
	if err != nil {
		return "", errors.Join(err, errors.New("could not detect ip"))
	}

	ip := strings.TrimSpace(string(output))

	return ip, nil
}

func main() {
	ctx := context.Background()
	ipv4Detected, err := getPublicIP("-4")
	if err != nil {
		slog.WarnContext(ctx, "could not detect ipv4 defaulting to empty string", "error", err)
	}
	ipv6Detected, err := getPublicIP("-6")
	if err != nil {
		slog.WarnContext(ctx, "could not detect ipv6 defaulting to empty string", "error", err)
	}

	m := model{
		stage:        formStage,
		detectedIPv4: ipv4Detected,
		detectedIPv6: ipv6Detected,
		inputs:       make([]textinput.Model, totalInputs),
	}

	var t textinput.Model
	for i := range m.inputs {
		t = textinput.New()
		t.Cursor.Style = cursorStyle
		t.CharLimit = 150

		switch i {
		case inputUsername:
			t.Placeholder = "Enter Username for ssh access"
			t.Focus()
			t.PromptStyle = focusedStyle
			t.TextStyle = focusedStyle
		case inputPassword:
			t.Placeholder = "Enter Password for ssh access"
		case inputCloudflareEmail:
			t.Placeholder = "Enter Cloudflare email"
		case inputCloudflareAPIKey:
			t.Placeholder = "Enter Cloudflare API key"
		case inputSSHPort:
			t.Placeholder = "Enter SSH port"
		case inputVPSIPv4:
			if m.detectedIPv4 != "" {
				t.Placeholder = fmt.Sprintf(
					"Detected IPv4: %s - verify this is correct",
					m.detectedIPv4,
				)
				t.SetValue(m.detectedIPv4)
			}

			if m.detectedIPv4 == "" {
				t.Placeholder = "No IPv4 auto-detected; enter manually"
			}
		case inputVPSIPv6:
			if m.detectedIPv6 != "" {
				t.Placeholder = fmt.Sprintf(
					"Detected IPv6: %s - verify this is correct",
					m.detectedIPv6,
				)
				t.SetValue(m.detectedIPv6)
			}
			if m.detectedIPv6 == "" {
				t.Placeholder = "No IPv6 auto-detected; enter manually if needed"
			}
		case inputDomain:
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
	if !finalModel.confirmed {
		fmt.Println("Provisioning cancelled; no changes were applied.")
		return
	}

	var domains []string
	var rootDomain string

	envVars := make(map[string]string, 9)

	envVars["USER_NAME"] = finalModel.form.Username
	envVars["USER_PASSWORD"] = finalModel.form.Password
	envVars["CLOUDFLARE_API_KEY"] = finalModel.form.CloudflareAPIKey
	envVars["SSH_PORT"] = finalModel.form.SSHPort

	rootDomain = finalModel.form.Domain

	for envName, prefix := range domainPrefix {
		fullDomain := prefix + "." + rootDomain

		envVars[envName] = fullDomain

		domains = append(domains, fullDomain)
	}

	if releaseVersion != "" {
		envVars["LATEST_RELEASE"] = releaseVersion
	}
	if releaseVersion == "" {
		envVars["LATEST_RELEASE"] = "latest"
	}

	envVars["ROOT_DOMAIN"] = rootDomain

	sessionKey, err := generateRandomHex(32)
	if err != nil {
		log.Fatal(err)
	}

	sessionEncryptionKey, err := generateRandomHex(32)
	if err != nil {
		log.Fatal(err)
	}

	tokenSigningKey, err := generateRandomHex(32)
	if err != nil {
		log.Fatal(err)
	}

	passwordSalt, err := generateRandomHex(16)
	if err != nil {
		log.Fatal(err)
	}

	envVars["SESSION_KEY"] = sessionKey
	envVars["SESSION_ENCRYPTION_KEY"] = sessionEncryptionKey
	envVars["TOKEN_SIGNING_KEY"] = tokenSigningKey
	envVars["PASSWORD_SALT"] = passwordSalt

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
			envVars["CLOUDFLARE_API_KEY"],
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
		_, err := client.DNS.Records.New(ctx, dns.RecordNewParams{
			ZoneID: cloudflare.F(zoneID),
			Body: dns.ARecordParam{
				Name:    cloudflare.F(domain),
				TTL:     cloudflare.F(dns.TTL1),
				Type:    cloudflare.F(dns.ARecordTypeA),
				Comment: cloudflare.F("added by mithlond - do not remove"),
				Content: cloudflare.F(finalModel.detectedIPv4),
				Proxied: cloudflare.F(true),
			},
		})
		if err != nil {
			panic(err)
		}

		if envVars["VPS_IPV6"] != "" {
			_, err := client.DNS.Records.New(ctx, dns.RecordNewParams{
				ZoneID: cloudflare.F(zoneID),
				Body: dns.AAAARecordParam{
					Name:    cloudflare.F(domain),
					TTL:     cloudflare.F(dns.TTL1),
					Type:    cloudflare.F(dns.AAAARecordTypeAAAA),
					Comment: cloudflare.F("added by mithlond - do not remove"),
					Content: cloudflare.F(finalModel.detectedIPv6),
					Proxied: cloudflare.F(true),
				},
			})
			if err != nil {
				panic(err)
			}

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
