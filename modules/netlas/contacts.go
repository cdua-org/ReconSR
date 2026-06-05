package netlas

import (
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/schema"
)

func formatEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func formatPerson(person string) string {
	return strings.TrimSpace(person)
}

func formatPhone(phone string) string {
	if phone == "" {
		return ""
	}
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, phone)
	if digits == "" || strings.TrimLeft(digits, "0") == "" {
		return ""
	}
	normalizedPhone := digits
	if strings.HasPrefix(strings.TrimSpace(phone), "+") {
		normalizedPhone = "+" + digits
	}
	return normalizedPhone
}

func isRedacted(val string) bool {
	lower := strings.ToLower(val)
	markers := []string{
		"redacted",
		"not disclosed",
		"please query",
		"data protected",
		"registration private",
		"contact privacy",
		"withheld for privacy",
		"select request email form",
		"visit www.icann.org",
		"not applicable",
		"gdpr masked",
		"statutory masking",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// ParseEmails deduplicates and validates a slice of emails before emitting them.
func ParseEmails(exec *schema.ModuleExecution, emails []string, category, targetValue string, isOOS bool, sourceRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	uniqueEmails := make(map[string]bool)
	for _, email := range emails {
		if strings.Contains(email, "whois") {
			continue
		}
		if isRedacted(email) {
			continue
		}
		formatted := formatEmail(email)
		if formatted == "" {
			continue
		}
		valEmailRes, err := validator.Validate(constants.TypeEmail, formatted)
		if err != nil {
			continue
		}
		valEmail := valEmailRes.Value
		if uniqueEmails[valEmail] {
			continue
		}
		uniqueEmails[valEmail] = true

		emailOOS := isOOS
		if targetValue != "" && orgdomain.IsEmailOutOfScope(valEmail, targetValue) {
			emailOOS = true
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       valEmailRes.Type,
			Category:   category,
			Value:      valEmailRes.Value,
			Source:     sourceRef,
			LocalID:    gen.NextID(),
			OutOfScope: emailOOS,
		})
	}
}

// ParsePhones deduplicates and normalizes a slice of phone numbers before emitting them.
func ParsePhones(exec *schema.ModuleExecution, phones []string, category string, isOOS bool, sourceRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	uniquePhones := make(map[string]bool)
	for _, phone := range phones {
		if isRedacted(phone) {
			continue
		}
		formatted := formatPhone(phone)
		if formatted == "" || uniquePhones[formatted] {
			continue
		}
		uniquePhones[formatted] = true

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       constants.TypePhone,
			Category:   category,
			Value:      formatted,
			Source:     sourceRef,
			LocalID:    gen.NextID(),
			OutOfScope: isOOS,
		})
	}
}

// ParseWhoisDates deduplicates identical WHOIS creation and update dates and emits them correctly.
func ParseWhoisDates(exec *schema.ModuleExecution, created, updated, prefix string, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	created = strings.TrimSpace(created)
	updated = strings.TrimSpace(updated)

	prefixStr := ""
	if prefix != "" {
		prefixStr = prefix + " "
	}
	if created != "" && updated != "" && created == updated {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    prefixStr + "Creation & Updated Date: " + created,
			Context:  "Whois Record (Merged)",
			Source:   targetRef,
			LocalID:  gen.NextID(),
		})
		return
	}
	if created != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    prefixStr + "Creation Date: " + created,
			Context:  "Whois Record (Created)",
			Source:   targetRef,
			LocalID:  gen.NextID(),
		})
	}
	if updated != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    prefixStr + "Updated Date: " + updated,
			Context:  "Whois Record (Updated)",
			Source:   targetRef,
			LocalID:  gen.NextID(),
		})
	}
}
