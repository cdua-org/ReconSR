package dns

import (
	"context"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func parseRPMailbox(mbox string) string {
	mbox = strings.TrimSuffix(mbox, ".")

	idx := strings.Index(mbox, ".")
	if idx <= 0 || idx == len(mbox)-1 {
		return mbox
	}

	return mbox[:idx] + "@" + mbox[idx+1:]
}

func processRPMailbox(mailbox, target string) []schema.ModuleResult {
	results := make([]schema.ModuleResult, 0, 1)

	if mailbox == "." || mailbox == "" {
		return results
	}

	res, vErr := validator.Validate(constants.TypeEmail, mailbox)
	if vErr != nil {
		log.Printf("%s skip_invalid_mailbox target=%q entity=%q err=%v", constants.FuncGetRP, target, mailbox, vErr)
		return results
	}

	isOOS := orgdomain.IsEmailOutOfScope(res.Value, target)
	log.Printf("%s result_mailbox target=%q entity=%q oos=%v", constants.FuncGetRP, target, res.Value, isOOS)

	results = append(results, schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Context:    "RP Administrator Email",
		OutOfScope: isOOS,
	})

	return results
}

func processRPTXTDomain(txtDomain, target string) []schema.ModuleResult {
	results := make([]schema.ModuleResult, 0, 1)

	txtDomain = strings.TrimSuffix(txtDomain, ".")
	if txtDomain == "." || txtDomain == "" {
		return results
	}

	res, vErr := validator.Validate(constants.TypeDomain, txtDomain)
	if vErr != nil {
		log.Printf("%s skip_invalid_txt_domain target=%q entity=%q err=%v", constants.FuncGetRP, target, txtDomain, vErr)
		return results
	}

	if res.Value == target {
		return results
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)
	log.Printf("%s result_txt_domain target=%q entity=%q oos=%v", constants.FuncGetRP, target, res.Value, isOOS)

	results = append(results, schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Tags:       []string{constants.TagRP},
		Context:    "RP TXT Reference Domain",
		OutOfScope: isOOS,
	})

	return results
}

func attachRPSource(results []schema.ModuleResult, source *schema.EntityRef) []schema.ModuleResult {
	for i := range results {
		results[i].Source = source
	}
	return results
}

func processRPRecord(record, target string) []schema.ModuleResult {
	results := make([]schema.ModuleResult, 0, 3)

	rpResult := schema.ModuleResult{
		Type:     constants.TypeRP,
		Category: constants.CategoryProperty,
		Value:    record,
	}
	results = append(results, rpResult)

	parts := strings.Fields(record)
	if len(parts) < 2 {
		return results
	}

	rpSource := &schema.EntityRef{Type: rpResult.Type, Value: rpResult.Value}
	mailbox := parseRPMailbox(parts[0])
	results = append(results, attachRPSource(processRPMailbox(mailbox, target), rpSource)...)
	results = append(results, attachRPSource(processRPTXTDomain(parts[1], target), rpSource)...)

	return results
}

func getRPData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetRP)

	log.Printf("%s query_start target=%q", constants.FuncGetRP, target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 17, nil)
	if err != nil {
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetRP, target, err)
		modutil.SetError(&exec, "rp lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	for _, rec := range records {
		exec.Results = append(exec.Results, processRPRecord(rec, target)...)
	}

	log.Printf("%s success target=%q results=%d", constants.FuncGetRP, target, len(exec.Results))

	return exec
}
