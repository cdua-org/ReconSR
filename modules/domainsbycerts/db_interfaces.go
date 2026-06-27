package domainsbycerts

import (
	"context"
	"database/sql"
	"fmt"
)

// QueryExecuter defines the database operations needed by fetchers.
type QueryExecuter interface {
	QueryContext(ctx context.Context, query string, args ...any) (RowScanner, error)
	Close() error
}

// RowScanner defines the operations for iterating over result rows.
type RowScanner interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close() error
}

type sqlDBWrapper struct {
	db *sql.DB
}

func (w *sqlDBWrapper) QueryContext(ctx context.Context, query string, args ...any) (RowScanner, error) {
	rows, err := w.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query context: %w", err)
	}
	if rErr := rows.Err(); rErr != nil {
		return nil, fmt.Errorf("rows err: %w", rErr)
	}
	return rows, nil
}

func (w *sqlDBWrapper) Close() error {
	if err := w.db.Close(); err != nil {
		return fmt.Errorf("close db: %w", err)
	}
	return nil
}
