package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
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

type provisioningResult struct {
	envVars       map[string]string
	hostnames     []string
	ipv4          string
	ipv6          string
	caddyUsername string
	caddyPassword string
}

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
	slog.Info("mithlond boot cli is loaded and fetching your IPs. it will be ready in 1 sec!")

	ipv4Detected, err := getPublicIP("-4")
	if err != nil {
		slog.Warn("could not detect ipv4 defaulting to empty string", "error", err)
	}
	ipv6Detected, err := getPublicIP("-6")
	if err != nil {
		slog.Warn("could not detect ipv6 defaulting to empty string", "error", err)
	}

	m := model{
		stage:             formStage,
		ipv4:              ipv4Detected,
		ipv6:              ipv6Detected,
		inputs:            make([]textinput.Model, totalInputs),
		invalidInputIndex: -1,
		loadingSpinner: spinner.New(
			spinner.WithSpinner(spinner.Dot),
			spinner.WithStyle(focusedStyle),
		),
		secretInputHidden: map[int]bool{
			inputPassword:         true,
			inputCloudflareAPIKey: true,
		},
	}

	var t textinput.Model
	for i := range m.inputs {
		t = textinput.New()
		t.Cursor.Style = cursorStyle
		t.CharLimit = 150
		t.Prompt = ""
		t.PromptStyle = noStyle
		t.PlaceholderStyle = helpStyle
		t.TextStyle = noStyle
		t.Width = 48

		switch i {
		case inputUsername:
			t.Placeholder = "Enter Username for ssh access"
			t.Focus()
			t.PromptStyle = focusedStyle
			t.TextStyle = focusedStyle
		case inputPassword:
			t.Placeholder = "Enter Password for ssh access"
			t.EchoMode = textinput.EchoPassword
			t.EchoCharacter = '*'
		case inputCloudflareEmail:
			t.Placeholder = "Enter Cloudflare email"
		case inputCloudflareAPIKey:
			t.Placeholder = "Enter Cloudflare API key"
			t.EchoMode = textinput.EchoPassword
			t.EchoCharacter = '*'
		case inputSSHPort:
			t.Placeholder = "Enter SSH port"
		case inputVPSIPv4:
			if m.ipv4 != "" {
				t.Placeholder = fmt.Sprintf(
					"Detected IPv4: %s - verify this is correct",
					m.ipv4,
				)
				t.SetValue(m.ipv4)
			}

			if m.ipv4 == "" {
				t.Placeholder = "No IPv4 auto-detected; enter manually"
			}
		case inputVPSIPv6:
			if m.ipv6 != "" {
				t.Placeholder = fmt.Sprintf(
					"Detected IPv6: %s - verify this is correct",
					m.ipv6,
				)
				t.SetValue(m.ipv6)
			}
			if m.ipv6 == "" {
				t.Placeholder = "No IPv6 auto-detected; enter manually if needed"
			}
		case inputDomain:
			t.Placeholder = "Enter domain name (e.g., example.com)"
		}

		m.inputs[i] = t
		m.ensureSecretVisibility(i)
	}

	p := tea.NewProgram(m)
	outputs, err := p.Run()
	if err != nil {
		fmt.Printf("could not start program: %s\n", err)
		os.Exit(1)
	}

	if finalModel, ok := outputs.(model); ok {
		if !finalModel.provisioningStarted {
			fmt.Println("Provisioning cancelled; no changes were applied.")
		}
	}
}

func runProvisioning(
	ctx context.Context,
	data formData,
	ipv4 string,
	ipv6 string,
) (provisioningResult, error) {
	result := provisioningResult{
		envVars: make(map[string]string, 16),
	}

	result.envVars["USER_NAME"] = data.Username
	result.envVars["USER_PASSWORD"] = data.Password
	result.envVars["CLOUDFLARE_API_KEY"] = data.CloudflareAPIKey
	result.envVars["SSH_PORT"] = data.SSHPort
	if strings.TrimSpace(data.CloudflareEmail) != "" {
		result.envVars["CLOUDFLARE_EMAIL"] = data.CloudflareEmail
	}

	rootDomain := strings.TrimSpace(data.Domain)
	result.envVars["ROOT_DOMAIN"] = rootDomain

	if releaseVersion != "" {
		result.envVars["LATEST_RELEASE"] = releaseVersion
	} else {
		result.envVars["LATEST_RELEASE"] = "latest"
	}

	for envName, prefix := range domainPrefix {
		fullDomain := fmt.Sprintf("%s.%s", prefix, rootDomain)
		result.envVars[envName] = fullDomain
		result.hostnames = append(result.hostnames, fullDomain)
	}

	result.ipv4 = ipv4
	result.ipv6 = ipv6

	sessionKey, err := generateRandomHex(32)
	if err != nil {
		return provisioningResult{}, fmt.Errorf("generate session key: %w", err)
	}
	sessionEncryptionKey, err := generateRandomHex(32)
	if err != nil {
		return provisioningResult{}, fmt.Errorf("generate session encryption key: %w", err)
	}
	tokenSigningKey, err := generateRandomHex(32)
	if err != nil {
		return provisioningResult{}, fmt.Errorf("generate token signing key: %w", err)
	}
	passwordSalt, err := generateRandomHex(16)
	if err != nil {
		return provisioningResult{}, fmt.Errorf("generate password salt: %w", err)
	}

	result.envVars["SESSION_KEY"] = sessionKey
	result.envVars["SESSION_ENCRYPTION_KEY"] = sessionEncryptionKey
	result.envVars["TOKEN_SIGNING_KEY"] = tokenSigningKey
	result.envVars["PASSWORD_SALT"] = passwordSalt

	caddyPassword := randomString(passwordLength)
	hash, err := bcrypt.GenerateFromPassword([]byte(caddyPassword), bcrypt.DefaultCost)
	if err != nil {
		return provisioningResult{}, fmt.Errorf("hash caddy password: %w", err)
	}

	result.envVars["CADDY_USER_NAME"] = result.envVars["USER_NAME"]
	result.envVars["CADDY_PASSWORD"] = string(hash)
	result.caddyUsername = result.envVars["USER_NAME"]
	result.caddyPassword = caddyPassword

	for key, value := range result.envVars {
		if err := os.Setenv(key, value); err != nil {
			return provisioningResult{}, fmt.Errorf("set env %s: %w", key, err)
		}
	}

	bootScript, err := scripts.Scripts.ReadFile("boot.sh")
	if err != nil {
		return provisioningResult{}, fmt.Errorf("read boot script: %w", err)
	}

	tempScriptPath := "/tmp/mithlond-boot.sh"
	if err := os.WriteFile(tempScriptPath, bootScript, 0o755); err != nil {
		return provisioningResult{}, fmt.Errorf("write temp boot script: %w", err)
	}
	defer os.Remove(tempScriptPath)

	cmd := exec.CommandContext(ctx, "/bin/bash", tempScriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		return provisioningResult{}, fmt.Errorf("run boot script: %w", err)
	}

	client := cloudflare.NewClient(option.WithAPIToken(result.envVars["CLOUDFLARE_API_KEY"]))
	if rootDomain == "" {
		return provisioningResult{}, errors.New("root domain is required to create DNS records")
	}

	res, err := client.Zones.List(ctx, zones.ZoneListParams{ // attempt to fetch zone for domain
		Name: cloudflare.F(rootDomain),
	})
	if err != nil {
		return provisioningResult{}, fmt.Errorf("list zones: %w", err)
	}

	var zoneID string
	for _, z := range res.Result {
		if z.Name == rootDomain {
			zoneID = z.ID
			break
		}
	}
	if zoneID == "" {
		return provisioningResult{}, fmt.Errorf("cloudflare zone not found for %s", rootDomain)
	}

	for _, domain := range result.hostnames {
		if result.ipv4 != "" {
			_, err := client.DNS.Records.New(ctx, dns.RecordNewParams{
				ZoneID: cloudflare.F(zoneID),
				Body: dns.ARecordParam{
					Name:    cloudflare.F(domain),
					TTL:     cloudflare.F(dns.TTL1),
					Type:    cloudflare.F(dns.ARecordTypeA),
					Comment: cloudflare.F("added by mithlond - do not remove"),
					Content: cloudflare.F(result.ipv4),
					Proxied: cloudflare.F(true),
				},
			})
			if err != nil {
				return provisioningResult{}, fmt.Errorf("create A record for %s: %w", domain, err)
			}
		}

		if result.ipv6 != "" {
			_, err := client.DNS.Records.New(ctx, dns.RecordNewParams{
				ZoneID: cloudflare.F(zoneID),
				Body: dns.AAAARecordParam{
					Name:    cloudflare.F(domain),
					TTL:     cloudflare.F(dns.TTL1),
					Type:    cloudflare.F(dns.AAAARecordTypeAAAA),
					Comment: cloudflare.F("added by mithlond - do not remove"),
					Content: cloudflare.F(result.ipv6),
					Proxied: cloudflare.F(true),
				},
			})
			if err != nil {
				return provisioningResult{}, fmt.Errorf(
					"create AAAA record for %s: %w",
					domain,
					err,
				)
			}
		}
	}

	slog.Info(
		"vps is now configured. save the following",
		"caddy_username", result.envVars["CADDY_USER_NAME"],
		"caddy_password", caddyPassword,
	)

	return result, nil
}

func rebootHost(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "sudo", "reboot")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}
