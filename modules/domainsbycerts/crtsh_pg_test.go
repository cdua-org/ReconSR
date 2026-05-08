package domainsbycerts

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestCrtshPgFetcher_Name(t *testing.T) {
	f := newCrtshPgFetcher()
	if name := f.Name(); name == "" {
		t.Errorf("expected non-empty name")
	}
}

func TestCrtshPgFetcher_Fetch_ConnError(t *testing.T) {
	f := &crtshPgFetcher{
		openDB: func(_ string) (*sql.DB, error) {
			return nil, errors.New("mock error")
		},
	}

	entries := f.Fetch(context.Background(), "search.example.com")
	if entries != nil {
		t.Errorf("expected nil entries on connection error, got %v", entries)
	}
}

func TestCrtshPgFetcher_Fetch_QueryError(t *testing.T) {
	f := &crtshPgFetcher{
		openDB: func(_ string) (*sql.DB, error) {
			return sql.Open("pgx", "postgres://guest@127.0.0.1:1/db?connect_timeout=1")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	entries := f.Fetch(ctx, "search.example.com")
	if entries != nil {
		t.Errorf("expected nil entries on query error, got %v", entries)
	}
}
