package main

import (
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"
)

type formValidationError struct {
	message    string
	inputIndex int
}

var (
	validatorOnce     sync.Once
	formValidatorInst *validator.Validate
)

func getFormValidator() *validator.Validate {
	validatorOnce.Do(func() {
		v := validator.New()
		v.RegisterValidation("root_domain", validateRootDomain)
		v.RegisterValidation("ssh_port", validateSSHPort)
		formValidatorInst = v
	})
	return formValidatorInst
}

func validateAndNormalizeFormData(data formData) (formData, *formValidationError) {
	sanitized := sanitizeFormData(data)

	if err := getFormValidator().Struct(sanitized); err != nil {
		var validationErrs validator.ValidationErrors
		if errors.As(err, &validationErrs) {
			return sanitized, firstValidationError(validationErrs)
		}

		return sanitized, &formValidationError{
			message:    "Validation failed.",
			inputIndex: -1,
		}
	}

	return sanitized, nil
}

func sanitizeFormData(data formData) formData {
	sanitized := data
	sanitized.Username = strings.TrimSpace(data.Username)
	sanitized.CloudflareEmail = strings.TrimSpace(data.CloudflareEmail)
	sanitized.CloudflareAPIKey = strings.TrimSpace(data.CloudflareAPIKey)
	sanitized.SSHPort = strings.TrimSpace(data.SSHPort)
	sanitized.VPSIPv4 = strings.TrimSpace(data.VPSIPv4)
	sanitized.VPSIPv6 = strings.TrimSpace(data.VPSIPv6)
	sanitized.Domain = strings.ToLower(strings.TrimSpace(data.Domain))
	return sanitized
}

func firstValidationError(errs validator.ValidationErrors) *formValidationError {
	if len(errs) == 0 {
		return &formValidationError{message: "Validation failed.", inputIndex: -1}
	}

	fieldToIndex := map[string]int{
		"CloudflareEmail": inputCloudflareEmail,
		"SSHPort":         inputSSHPort,
		"VPSIPv4":         inputVPSIPv4,
		"VPSIPv6":         inputVPSIPv6,
		"Domain":          inputDomain,
	}

	orderedFields := []string{
		"CloudflareEmail",
		"SSHPort",
		"VPSIPv4",
		"VPSIPv6",
		"Domain",
	}

	for _, field := range orderedFields {
		if fe := fieldErrorForField(errs, field); fe != nil {
			idx := -1
			if mapped, ok := fieldToIndex[field]; ok {
				idx = mapped
			}
			return &formValidationError{
				message:    validationMessage(field, fe.Tag()),
				inputIndex: idx,
			}
		}
	}

	fe := errs[0]
	field := fe.StructField()
	idx := -1
	if mapped, ok := fieldToIndex[field]; ok {
		idx = mapped
	}

	return &formValidationError{
		message:    validationMessage(field, fe.Tag()),
		inputIndex: idx,
	}
}

func fieldErrorForField(errs validator.ValidationErrors, field string) validator.FieldError {
	for _, err := range errs {
		if err.StructField() == field {
			return err
		}
	}
	return nil
}

func validationMessage(field, tag string) string {
	switch field {
	case "CloudflareEmail":
		if tag == "required" {
			return "Cloudflare email is required."
		}
		return "Enter a valid Cloudflare email address (e.g. user@example.com)."
	case "SSHPort":
		if tag == "required" {
			return "SSH port is required."
		}
		return "SSH port must be a number between 1 and 65535. Port 80 and 443 is reserved."
	case "VPSIPv4":
		return "IPv4 must be a valid IPv4 address."
	case "VPSIPv6":
		return "IPv6 must be a valid IPv6 address."
	case "Domain":
		if tag == "required" {
			return "Root domain is required."
		}
		return "Enter a valid domain such as example.com (no http:// or paths)."
	default:
		return "One or more fields are invalid."
	}
}

func validateRootDomain(fl validator.FieldLevel) bool {
	domain := strings.TrimSpace(fl.Field().String())
	if domain == "" {
		return false
	}

	if strings.Contains(domain, "://") {
		return false
	}

	if strings.ContainsAny(domain, "/\\ ") {
		return false
	}

	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	last := parts[len(parts)-1]
	if len(last) < 2 {
		return false
	}

	for _, part := range parts {
		if part == "" {
			return false
		}
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		for _, r := range part {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}

	return true
}

func validateSSHPort(fl validator.FieldLevel) bool {
	portStr := strings.TrimSpace(fl.Field().String())
	if portStr == "" {
		return false
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}

	if port == 80 || port == 443 {
		return false
	}

	return port >= 1 && port <= 65535
}
