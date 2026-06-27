package domainsbycerts

import (
	"cdua-org/ReconSR/modules/utils/resolver"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"
)

type mockQueryExecuter struct {
	queryContextFunc func(ctx context.Context, query string, args ...any) (RowScanner, error)
	closeFunc        func() error
}

func (m *mockQueryExecuter) QueryContext(ctx context.Context, query string, args ...any) (RowScanner, error) {
	if m.queryContextFunc != nil {
		return m.queryContextFunc(ctx, query, args...)
	}
	return nil, errors.New("not implemented")
}

func (m *mockQueryExecuter) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

type mockRowScanner struct {
	nextFunc  func() bool
	scanFunc  func(dest ...any) error
	errFunc   func() error
	closeFunc func() error
}

func (m *mockRowScanner) Next() bool {
	if m.nextFunc != nil {
		return m.nextFunc()
	}
	return false
}

func (m *mockRowScanner) Scan(dest ...any) error {
	if m.scanFunc != nil {
		return m.scanFunc(dest...)
	}
	return nil
}

func (m *mockRowScanner) Err() error {
	if m.errFunc != nil {
		return m.errFunc()
	}
	return nil
}

func (m *mockRowScanner) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func TestCrtshPgFetcher_Name(t *testing.T) {
	f := newCrtshPgFetcher()
	if name := f.Name(); name == "" {
		t.Errorf("expected non-empty name")
	}
}

func TestCrtshPgFetcher_NewCrtshPgFetcher(t *testing.T) {
	f, ok := newCrtshPgFetcher().(*crtshPgFetcher)
	if !ok {
		t.Fatalf("expected *crtshPgFetcher")
	}
	db, err := f.openDB("postgres://invalid")
	if err != nil {
		t.Errorf("expected no error from sql.Open, got %v", err)
	}
	if db != nil {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("db close error: %v", cerr)
		}
	}
}

func TestCrtshPgFetcher_Fetch_ConnError(t *testing.T) {
	f := &crtshPgFetcher{
		openDB: func(_ string) (QueryExecuter, error) {
			return nil, errors.New("mock conn error")
		},
	}

	entries := f.Fetch(context.Background(), "node4.example.org")
	if entries != nil {
		t.Errorf("expected nil entries on connection error, got %v", entries)
	}
}

func TestCrtshPgFetcher_Fetch_QueryError(t *testing.T) {
	f := &crtshPgFetcher{
		openDB: func(_ string) (QueryExecuter, error) {
			return &mockQueryExecuter{
				queryContextFunc: func(_ context.Context, _ string, _ ...any) (RowScanner, error) {
					return nil, errors.New("mock query error")
				},
			}, nil
		},
	}

	entries := f.Fetch(context.Background(), "node4.example.org")
	if entries != nil {
		t.Errorf("expected nil entries on query error, got %v", entries)
	}
}

func TestCrtshPgFetcher_Fetch_Success(t *testing.T) {
	rowsData := []struct {
		name     string
		notAfter sql.NullTime
	}{
		{"node4.example.org", sql.NullTime{Time: time.Now(), Valid: true}},
		{"node5.example.org\n \n\nnode6.example.org", sql.NullTime{Valid: false}},
	}
	idx := -1

	mockRows := &mockRowScanner{
		nextFunc: func() bool {
			idx++
			return idx < len(rowsData)
		},
		scanFunc: func(dest ...any) error {
			if idx >= len(rowsData) {
				return errors.New("EOF")
			}
			if strPtr, ok := dest[0].(*string); ok {
				*strPtr = rowsData[idx].name
			}
			if timePtr, ok := dest[1].(*sql.NullTime); ok {
				*timePtr = rowsData[idx].notAfter
			}
			return nil
		},
	}

	f := &crtshPgFetcher{
		openDB: func(_ string) (QueryExecuter, error) {
			return &mockQueryExecuter{
				queryContextFunc: func(_ context.Context, _ string, _ ...any) (RowScanner, error) {
					return mockRows, nil
				},
			}, nil
		},
	}

	entries := f.Fetch(context.Background(), "search.example.com")
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].value != "node4.example.org" {
		t.Errorf("expected node4, got %s", entries[0].value)
	}
	if entries[1].value != "node5.example.org" {
		t.Errorf("expected node5, got %s", entries[1].value)
	}
	if entries[2].value != "node6.example.org" {
		t.Errorf("expected node6, got %s", entries[2].value)
	}
}

func TestCrtshPgFetcher_Fetch_ScanError(t *testing.T) {
	idx := -1
	mockRows := &mockRowScanner{
		nextFunc: func() bool {
			idx++
			return idx < 1
		},
		scanFunc: func(_ ...any) error {
			return errors.New("mock scan error")
		},
	}

	f := &crtshPgFetcher{
		openDB: func(_ string) (QueryExecuter, error) {
			return &mockQueryExecuter{
				queryContextFunc: func(_ context.Context, _ string, _ ...any) (RowScanner, error) {
					return mockRows, nil
				},
			}, nil
		},
	}

	entries := f.Fetch(context.Background(), "node7.example.org")
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries due to scan error, got %d", len(entries))
	}
}

func TestCrtshPgFetcher_Fetch_RowsErr(t *testing.T) {
	mockRows := &mockRowScanner{
		nextFunc: func() bool { return false },
		errFunc:  func() error { return errors.New("mock rows error") },
	}

	f := &crtshPgFetcher{
		openDB: func(_ string) (QueryExecuter, error) {
			return &mockQueryExecuter{
				queryContextFunc: func(_ context.Context, _ string, _ ...any) (RowScanner, error) {
					return mockRows, nil
				},
			}, nil
		},
	}

	entries := f.Fetch(context.Background(), "node7.example.org")
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries due to rows error, got %d", len(entries))
	}
}

func TestCrtshPgFetcher_Fetch_CloseErrors(t *testing.T) {
	mockRows := &mockRowScanner{
		nextFunc:  func() bool { return false },
		closeFunc: func() error { return errors.New("mock rows close error") },
	}

	f := &crtshPgFetcher{
		openDB: func(_ string) (QueryExecuter, error) {
			return &mockQueryExecuter{
				queryContextFunc: func(_ context.Context, _ string, _ ...any) (RowScanner, error) {
					return mockRows, nil
				},
				closeFunc: func() error { return errors.New("mock db close error") },
			}, nil
		},
	}

	entries := f.Fetch(context.Background(), "node8.example.org")
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestSqlDBWrapper_Coverage(t *testing.T) {
	sql.Register("fakedriver", &fakeDriver{})

	dbErr, err := sql.Open("fakedriver", "fake")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cerr := dbErr.Close(); cerr != nil {
		t.Logf("close err: %v", cerr)
	}
	wrapperErr := &sqlDBWrapper{db: dbErr}
	if _, qerr := wrapperErr.QueryContext(context.Background(), "SELECT 1"); qerr == nil {
		t.Logf("expected query error with closed db")
	}
	dbSuccess, err := sql.Open("fakedriver", "fake")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	wrapperSuccess := &sqlDBWrapper{db: dbSuccess}
	if _, qerr := wrapperSuccess.QueryContext(context.Background(), "SELECT 1"); qerr != nil {
		t.Errorf("unexpected query error: %v", qerr)
	}
	if cerr := wrapperSuccess.Close(); cerr != nil {
		t.Errorf("unexpected close error: %v", cerr)
	}
	if cerr := dbErr.Close(); cerr != nil {
		t.Logf("expected close error or success, got: %v", cerr)
	}

	dbCloseErr, err := sql.Open("fakedriver", "close_err")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := dbCloseErr.PingContext(context.Background()); err != nil {
		t.Logf("expected ping error or success: %v", err)
	}
	wrapperCloseErr := &sqlDBWrapper{db: dbCloseErr}
	if cerr := wrapperCloseErr.Close(); cerr == nil {
		t.Errorf("expected close error")
	}
}

type fakeDriver struct{}

func (d *fakeDriver) Open(name string) (driver.Conn, error) {
	return &fakeConn{name: name}, nil
}

type fakeConn struct {
	name string
}

func (c *fakeConn) Prepare(_ string) (driver.Stmt, error) {
	return &fakeStmt{}, nil
}

func (c *fakeConn) Close() error {
	if c.name == "close_err" {
		return errors.New("mock close error")
	}
	return nil
}

func (c *fakeConn) Begin() (driver.Tx, error) {
	return nil, errors.New("not implemented")
}

type fakeStmt struct{}

func (s *fakeStmt) Close() error { return nil }

func (s *fakeStmt) NumInput() int { return -1 }

func (s *fakeStmt) Exec(_ []driver.Value) (driver.Result, error) {
	return nil, errors.New("not implemented")
}

func (s *fakeStmt) Query(_ []driver.Value) (driver.Rows, error) {
	return &fakeDriverRows{}, nil
}

type fakeDriverRows struct{}

func (r *fakeDriverRows) Columns() []string { return []string{"col1"} }

func (r *fakeDriverRows) Close() error { return nil }

func (r *fakeDriverRows) Next(_ []driver.Value) error {
	return errors.New("EOF")
}

func TestCrtshPgFetcher_Fetch_TimeoutFallback(t *testing.T) {
	origTimeout := resolver.CrtshPGTimeout
	resolver.CrtshPGTimeout = 0
	defer func() { resolver.CrtshPGTimeout = origTimeout }()

	mockRows := &mockRowScanner{
		nextFunc: func() bool { return false },
	}

	f := &crtshPgFetcher{
		openDB: func(_ string) (QueryExecuter, error) {
			return &mockQueryExecuter{
				queryContextFunc: func(_ context.Context, _ string, _ ...any) (RowScanner, error) {
					return mockRows, nil
				},
			}, nil
		},
	}

	entries := f.Fetch(context.Background(), "example.com")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestCrtshPgFetcher_Fetch_JSONMarshalError(t *testing.T) {
	origJSONMarshal := jsonMarshal
	jsonMarshal = func(_ any) ([]byte, error) {
		return nil, errors.New("mock json marshal error")
	}
	defer func() { jsonMarshal = origJSONMarshal }()

	mockRows := &mockRowScanner{
		nextFunc: func() bool {
			return true
		},
	}

	callCount := 0
	mockRows.nextFunc = func() bool {
		callCount++
		return callCount == 1
	}

	mockRows.scanFunc = func(dest ...any) error {
		if strPtr, ok := dest[0].(*string); ok {
			*strPtr = "example.com"
		}
		if timePtr, ok := dest[1].(*sql.NullTime); ok {
			*timePtr = sql.NullTime{Valid: false}
		}
		return nil
	}

	f := &crtshPgFetcher{
		openDB: func(_ string) (QueryExecuter, error) {
			return &mockQueryExecuter{
				queryContextFunc: func(_ context.Context, _ string, _ ...any) (RowScanner, error) {
					return mockRows, nil
				},
			}, nil
		},
	}

	entries := f.Fetch(context.Background(), "example.com")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].rawData != nil {
		t.Errorf("expected rawData to be nil on marshal error")
	}
}

func TestDefaultPgOpenDB_SqlOpenError(t *testing.T) {
	origSQLOpen := sqlOpen
	sqlOpen = func(_, _ string) (*sql.DB, error) {
		return nil, errors.New("mock sql open error")
	}
	defer func() { sqlOpen = origSQLOpen }()

	_, err := defaultPgOpenDB("dummy")
	if err == nil || !strings.Contains(err.Error(), "mock sql open error") {
		t.Errorf("expected mock sql open error, got %v", err)
	}
}
