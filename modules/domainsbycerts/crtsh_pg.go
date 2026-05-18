package domainsbycerts

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	// Register standard library PostgreSQL driver.
	_ "github.com/jackc/pgx/v5/stdlib"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
)

type crtshPgFetcher struct {
	openDB func(dsn string) (*sql.DB, error)
}

func newCrtshPgFetcher() CertFetcher {
	return &crtshPgFetcher{
		openDB: func(dsn string) (*sql.DB, error) {
			return sql.Open("pgx", dsn)
		},
	}
}

func (f *crtshPgFetcher) Name() string {
	return "crt.sh-pg"
}

func (f *crtshPgFetcher) Fetch(ctx context.Context, target string) []certificateIdentityEntry {
	timeout := resolver.CrtshPGTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	qCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dsn := "postgres://guest@crt.sh:5432/certwatch?default_query_exec_mode=simple_protocol&sslmode=disable"
	db, err := f.openDB(dsn)
	if err != nil {
		dbg.Printf("%s error source=%q target=%q stage=open_db err=%v", constants.FuncGetDomains, f.Name(), target, err)
		return nil
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			dbg.Printf("%s db_close_failed source=%q target=%q err=%v", constants.FuncGetDomains, f.Name(), target, cerr)
		}
	}()

	query := `
		SELECT sub.NAME_VALUE, cl.NOT_AFTER
		FROM (
			SELECT cai.CERTIFICATE_ID, cai.NAME_VALUE
			FROM certificate_and_identities cai
			WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
			  AND cai.NAME_VALUE ILIKE ('%.' || $1)
			LIMIT 10000
		) sub
		LEFT JOIN certificate_lifecycle cl ON sub.CERTIFICATE_ID = cl.CERTIFICATE_ID;
	`
	rows, err := db.QueryContext(qCtx, query, target)
	if err != nil {
		dbg.Printf("%s error source=%q target=%q stage=query err=%v", constants.FuncGetDomains, f.Name(), target, err)
		return nil
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			dbg.Printf("%s rows_close_failed source=%q target=%q err=%v", constants.FuncGetDomains, f.Name(), target, cerr)
		}
	}()

	var entries []certificateIdentityEntry
	type rawRecord struct {
		NameValue string `json:"name_value"`
		NotAfter  string `json:"not_after,omitempty"`
	}
	var rawRecords []rawRecord

	for rows.Next() {
		var nameValue string
		var notAfter sql.NullTime

		if err := rows.Scan(&nameValue, &notAfter); err != nil {
			dbg.Printf("%s skip_row_scan_failed source=%q target=%q err=%v", constants.FuncGetDomains, f.Name(), target, err)
			continue
		}

		var notAfterStr string
		if notAfter.Valid {
			notAfterStr = notAfter.Time.Format(time.RFC3339)
		}

		rawRecords = append(rawRecords, rawRecord{
			NameValue: nameValue,
			NotAfter:  notAfterStr,
		})

		for name := range strings.SplitSeq(nameValue, "\n") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			entries = append(entries, certificateIdentityEntry{
				value:    name,
				notAfter: notAfter.Time,
			})
		}
	}

	if err := rows.Err(); err != nil {
		dbg.Printf("%s error source=%q target=%q stage=iterate_rows err=%v", constants.FuncGetDomains, f.Name(), target, err)
	}

	if len(rawRecords) > 0 {
		if rawBytes, err := json.Marshal(rawRecords); err == nil {
			for i := range entries {
				entries[i].rawData = rawBytes
			}
		} else {
			dbg.Printf("%s raw_marshal_failed source=%q target=%q err=%v", constants.FuncGetDomains, f.Name(), target, err)
		}
	}

	return entries
}
