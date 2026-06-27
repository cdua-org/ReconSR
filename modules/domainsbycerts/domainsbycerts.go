// Package domainsbycerts discovers certificate identities from Certificate Transparency logs.
package domainsbycerts

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const (
	timeFormatRFC3339  = "2006-01-02T15:04:05Z07:00"
	timeFormatDateTime = "2006-01-02T15:04:05"
	timeFormatDate     = "2006-01-02 15:04:05"
	identityKindTarget = "target"
)

type module struct{}

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "domainsbycerts"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{constants.FuncGetDomains},
		InputTypes: []string{constants.TypeDomain},
		CustomFunctions: map[string]schema.FunctionCapabilities{
			constants.FuncGetDomains: {
				Limit:   3,
				DelayMs: 2000,
			},
		},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		switch f {
		case constants.FuncGetDomains:
			execution = getDomains(data.Target.Value)
		default:
			errMsg := "unsupported function: " + f
			execution = schema.ModuleExecution{
				Function: f,
				Error:    &errMsg,
			}
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}

func getDomains(target string) schema.ModuleExecution {
	execution := modutil.NewExecution(constants.FuncGetDomains)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	allIdentities := collectAllIdentities(ctx, target)

	if len(allIdentities.identities) == 0 {
		dbg.Printf("%s error target=%q stage=collect_identities reason=no_identities", constants.FuncGetDomains, target)
		errMsg := "all cert discovery methods exhausted for " + target
		execution.Error = &errMsg
		return execution
	}

	disableCertExpiredSubdomains := false
	if val, ok := resolver.GetOption("DisableCertExpiredSubdomains"); ok && strings.EqualFold(val, "true") {
		disableCertExpiredSubdomains = true
	}

	gen := modutil.NewLocalIDGenerator()

	execution.RawData = allIdentities.rawData
	classified := classifyIdentities(allIdentities.identities, target)
	execution.Results = formatResults(classified, disableCertExpiredSubdomains, gen)

	sort.Slice(execution.Results, func(i, j int) bool {
		return execution.Results[i].Value < execution.Results[j].Value
	})

	dbg.Printf("%s success target=%q identities=%d results=%d", constants.FuncGetDomains, target, len(allIdentities.identities), len(execution.Results))

	return execution
}

type certificateIdentitySource struct {
	NotAfter time.Time
	value    string
	source   string
}

type collectedIdentities struct {
	rawData    string
	identities []certificateIdentitySource
}

type certificateIdentityEntry struct {
	value    string
	notAfter time.Time
	rawData  json.RawMessage
}

// CertFetcher defines the interface for certificate transparency APIs.
type CertFetcher interface {
	Fetch(ctx context.Context, target string) []certificateIdentityEntry
	Name() string
}

func collectAllIdentities(ctx context.Context, target string) collectedIdentities {
	var result collectedIdentities
	rawPayloads := make(map[string]json.RawMessage)

	disableCertspotter := false
	if val, ok := resolver.GetOption("DisableCertspotter"); ok && strings.EqualFold(val, "true") {
		disableCertspotter = true
	}

	disableCrtshPG := false
	if val, ok := resolver.GetOption("DisableCrtshPG"); ok && strings.EqualFold(val, "true") {
		disableCrtshPG = true
	}

	var fetchers []CertFetcher
	if !disableCertspotter {
		fetchers = append(fetchers, newCertspotterFetcher())
	} else {
		dbg.Printf("%s certspotter_disabled=true target=%q", constants.FuncGetDomains, target)
	}

	if !disableCrtshPG {
		fetchers = append(fetchers, newCrtshPgFetcher())
	} else {
		dbg.Printf("%s crtsh_pg_disabled=true target=%q", constants.FuncGetDomains, target)
	}

	fetchers = append(fetchers, newCrtshFetcher())

	for _, f := range fetchers {
		entries := f.Fetch(ctx, target)

		dbg.Printf("%s fetcher=%q target=%q entries=%d", constants.FuncGetDomains, f.Name(), target, len(entries))

		if len(entries) > 0 {
			for _, entry := range entries {
				result.identities = append(result.identities, certificateIdentitySource{
					value:    entry.value,
					source:   f.Name(),
					NotAfter: entry.notAfter,
				})
			}
			if len(rawPayloads) == 0 {
				rawPayloads[f.Name()] = entries[0].rawData
			}

			break
		}
	}

	dbg.Printf("%s identities_total=%d target=%q", constants.FuncGetDomains, len(result.identities), target)

	if combined, err := json.Marshal(rawPayloads); err == nil {
		result.rawData = string(combined)
	}

	return result
}

type classifiedIdentity struct {
	notAfter time.Time
	source   string
}

type classifiedIdentities struct {
	subdomains      map[string]classifiedIdentity
	emails          map[string]classifiedIdentity
	targetMaxExpiry time.Time
	targetSource    string
}

type matchedIdentity struct {
	kind  string
	value string
}

func classifyIdentities(identities []certificateIdentitySource, target string) classifiedIdentities {
	target = normalizeDomain(target)
	result := classifiedIdentities{
		subdomains: make(map[string]classifiedIdentity),
		emails:     make(map[string]classifiedIdentity),
	}
	var targetCount, skippedCount, subdomainCount, emailCount int

	for _, identity := range identities {
		if !matchesTargetIdentity(identity.value, target) {
			skippedCount++
			if skippedCount <= 10 {
				dbg.Printf("%s skip_unrelated_identity=%q target=%q", constants.FuncGetDomains, identity.value, target)
			}
			continue
		}

		matched, ok := classifyMatchedIdentity(identity.value, target)
		if !ok {
			skippedCount++
			if skippedCount <= 10 {
				dbg.Printf("%s skip_invalid_identity=%q", constants.FuncGetDomains, identity.value)
			}
			continue
		}

		switch matched.kind {
		case identityKindTarget:
			targetCount++
			if identity.NotAfter.After(result.targetMaxExpiry) {
				result.targetMaxExpiry = identity.NotAfter
				result.targetSource = identity.source
			}
		case constants.TypeSubdomain:
			subdomainCount++
			if identity.NotAfter.After(result.subdomains[matched.value].notAfter) {
				result.subdomains[matched.value] = classifiedIdentity{
					notAfter: identity.NotAfter,
					source:   identity.source,
				}
			}
		case constants.TypeEmail:
			emailCount++
			if identity.NotAfter.After(result.emails[matched.value].notAfter) {
				result.emails[matched.value] = classifiedIdentity{
					notAfter: identity.NotAfter,
					source:   identity.source,
				}
			}
		}
	}

	dbg.Printf("%s classify target_hits=%d skipped=%d valid_subdomains=%d unique_subdomains=%d valid_emails=%d unique_emails=%d",
		constants.FuncGetDomains, targetCount, skippedCount, subdomainCount, len(result.subdomains), emailCount, len(result.emails))

	return result
}

func formatResults(classified classifiedIdentities, disableCertExpiredSubdomains bool, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	now := time.Now()
	results := make([]schema.ModuleResult, 0, len(classified.subdomains)*3+len(classified.emails)*3+2)
	var expiredDomains []string

	if !classified.targetMaxExpiry.IsZero() && classified.targetMaxExpiry.After(now) {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeCertNotAfter,
			Category: constants.CategoryProperty,
			Value:    classified.targetMaxExpiry.Format(time.DateTime),
			Context:  classified.targetSource,
			LocalID:  gen.NextID(),
		})
	}
	results = appendSubdomainResults(results, classified.subdomains, now, disableCertExpiredSubdomains, &expiredDomains, gen)
	results = appendEmailResults(results, classified.emails, now, gen)

	if len(expiredDomains) > 0 {
		sort.Strings(expiredDomains)
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeCertExpiredSubdomains,
			Category: constants.CategoryProperty,
			Value:    strings.Join(expiredDomains, ", "),
			Context:  "Expired Certificates",
			LocalID:  gen.NextID(),
		})
	}

	dbg.Printf("%s format_results=%d expired_subdomains=%d emails=%d", constants.FuncGetDomains, len(results), len(expiredDomains), len(classified.emails))

	return results
}

func appendSubdomainResults(results []schema.ModuleResult, subdomains map[string]classifiedIdentity, now time.Time, disableCertExpiredSubdomains bool, expiredDomains *[]string, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	for subdomain, identity := range subdomains {
		isExpired := !identity.notAfter.IsZero() && !identity.notAfter.After(now)

		if isExpired && !disableCertExpiredSubdomains {
			*expiredDomains = append(*expiredDomains, subdomain+" ("+identity.notAfter.Format(time.DateTime)+")")
			continue
		}

		tags := []string{constants.TagSan, constants.TagCTLog}
		if isExpired {
			tags = append(tags, constants.TagHistorical)
		}

		resultValue := subdomain
		result := schema.ModuleResult{
			Type:     constants.TypeSubdomain,
			Category: constants.CategoryNode,
			Value:    resultValue,
			Context:  identity.source,
			Applied:  true,
			LocalID:  gen.NextID(),
		}
		if trimmedWildcard, ok := strings.CutPrefix(subdomain, "*."); ok {
			resultValue = trimmedWildcard
			result.Value = resultValue
			tags = append(tags, constants.TagWildcard)
			result.Context = subdomain
		}
		result.Tags = tags

		results = append(results, result)

		if identity.notAfter.IsZero() {
			continue
		}

		dateVal := identity.notAfter.Format(time.DateTime)
		dateLocalID := gen.NextID()
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeCertNotAfter,
			Category: constants.CategoryProperty,
			Value:    dateVal,
			LocalID:  dateLocalID,
			Source: &schema.EntityRef{
				Type:    constants.TypeSubdomain,
				Value:   resultValue,
				LocalID: result.LocalID,
			},
		})

		if isExpired {
			results = append(results, schema.ModuleResult{
				Type:     constants.TypeStatus,
				Category: constants.CategoryProperty,
				Value:    constants.StatusExpired,
				LocalID:  gen.NextID(),
				Source: &schema.EntityRef{
					Type:    constants.TypeCertNotAfter,
					Value:   dateVal,
					LocalID: dateLocalID,
				},
			})
		}
	}
	return results
}

func appendEmailResults(results []schema.ModuleResult, emails map[string]classifiedIdentity, now time.Time, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	for email, identity := range emails {
		isExpired := !identity.notAfter.IsZero() && !identity.notAfter.After(now)

		tags := []string{constants.TagSan, constants.TagCTLog}
		if isExpired {
			tags = append(tags, constants.TagHistorical)
		}

		emailLocalID := gen.NextID()
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeEmail,
			Category: constants.CategoryNode,
			Value:    email,
			Context:  identity.source,
			Applied:  true,
			Tags:     tags,
			LocalID:  emailLocalID,
		})

		if identity.notAfter.IsZero() {
			continue
		}

		dateVal := identity.notAfter.Format(time.DateTime)
		dateLocalID := gen.NextID()
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeDomainCertNotAfter,
			Category: constants.CategoryProperty,
			Value:    dateVal,
			LocalID:  dateLocalID,
			Source: &schema.EntityRef{
				Type:    constants.TypeEmail,
				Value:   email,
				LocalID: emailLocalID,
			},
		})

		if isExpired {
			results = append(results, schema.ModuleResult{
				Type:     constants.TypeStatus,
				Category: constants.CategoryProperty,
				Value:    constants.StatusExpired,
				LocalID:  gen.NextID(),
				Source: &schema.EntityRef{
					Type:    constants.TypeDomainCertNotAfter,
					Value:   dateVal,
					LocalID: dateLocalID,
				},
			})
		}
	}
	return results
}

func normalizeDomain(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func matchesTargetIdentity(value, target string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}

	if strings.Contains(value, "@") {
		_, emailDomain, ok := strings.Cut(strings.ToLower(value), "@")
		return ok && matchesTargetDomain(emailDomain, target)
	}

	domainValue := normalizeDomain(strings.TrimPrefix(value, "*."))
	return matchesTargetDomain(domainValue, target)
}

func matchesTargetDomain(domainValue, target string) bool {
	domainValue = strings.TrimSuffix(normalizeDomain(domainValue), ".")
	return domainValue == target || strings.HasSuffix(domainValue, "."+target)
}

func classifyMatchedIdentity(value, target string) (matchedIdentity, bool) {
	if strings.Contains(value, "@") {
		return classifyEmailIdentity(value, target)
	}
	return classifyDomainIdentity(value, target)
}

func classifyEmailIdentity(value, target string) (matchedIdentity, bool) {
	validated, err := validator.Validate(constants.TypeEmail, strings.TrimSpace(value))
	if err != nil || validated.Type != constants.TypeEmail {
		return matchedIdentity{}, false
	}

	_, emailDomain, ok := strings.Cut(validated.Value, "@")
	if !ok || !matchesTargetDomain(emailDomain, target) {
		return matchedIdentity{}, false
	}

	return matchedIdentity{kind: constants.TypeEmail, value: validated.Value}, true
}

func classifyDomainIdentity(value, target string) (matchedIdentity, bool) {
	trimmedValue := strings.TrimSpace(value)
	isWildcard := strings.HasPrefix(trimmedValue, "*.")
	validatedValue := strings.TrimPrefix(trimmedValue, "*.")

	validated, err := validator.Validate(constants.TypeDomain, validatedValue)
	if err != nil || !matchesTargetDomain(validated.Value, target) {
		return matchedIdentity{}, false
	}

	if validated.Value == target && !isWildcard {
		return matchedIdentity{kind: identityKindTarget, value: validated.Value}, true
	}

	resultValue := validated.Value
	if isWildcard {
		resultValue = "*." + validated.Value
	}

	return matchedIdentity{kind: constants.TypeSubdomain, value: resultValue}, true
}

func parseCertTimestamp(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}

	if t, err := time.Parse(timeFormatRFC3339, ts); err == nil {
		return t
	}

	if t, err := time.Parse(timeFormatDateTime, ts); err == nil {
		return t
	}

	if t, err := time.Parse(timeFormatDate, ts); err == nil {
		return t
	}

	return time.Time{}
}
