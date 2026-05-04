package repository

import (
	"cdua-org/ReconSR/schema"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type routeRegistry struct {
	mu     sync.RWMutex
	routes map[string]string
}

var activeRoutes = &routeRegistry{
	routes: make(map[string]string),
}

func generateRouteRef() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// AllocateWorkspaceRoute reserves a new route for the workspace context.
func AllocateWorkspaceRoute(internalName string) string {
	activeRoutes.mu.Lock()
	defer activeRoutes.mu.Unlock()

	ref := generateRouteRef()
	activeRoutes.routes[ref] = internalName
	return ref
}

// ResolveWorkspaceRoute translates a route reference to the internal context.
func ResolveWorkspaceRoute(ref string) (string, error) {
	activeRoutes.mu.RLock()
	defer activeRoutes.mu.RUnlock()

	internalName, exists := activeRoutes.routes[ref]
	if !exists {
		return "", errors.New("workspace route is invalid or detached")
	}
	return internalName, nil
}

// SyncMasterDB creates or updates the master database with projects and available modules.
func SyncMasterDB(ctx context.Context, regs []schema.ModuleRegistration) (err error) {
	baseDir := filepath.Join("storage", "base")
	if err := os.MkdirAll(baseDir, 0750); err != nil {
		return err
	}

	dbPath := filepath.Join(baseDir, "master.db")
	db, dbErr := sql.Open("sqlite", dbPath)
	if dbErr != nil {
		return dbErr
	}
	defer func() {
		cerr := db.Close()
		if err == nil {
			err = cerr
		}
	}()

	createProjects := `CREATE TABLE IF NOT EXISTS projects (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		db_identifier TEXT NOT NULL,
		initial_target_type TEXT NOT NULL,
		initial_target_value TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.ExecContext(ctx, createProjects); err != nil {
		return err
	}

	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS modules;"); err != nil {
		return err
	}

	createModules := `CREATE TABLE modules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		module_name TEXT NOT NULL,
		function TEXT NOT NULL,
		input_type TEXT NOT NULL,
		is_enabled BOOLEAN DEFAULT 1
	);`
	if _, err := db.ExecContext(ctx, createModules); err != nil {
		return err
	}

	type modRecord struct {
		name, fn, itype string
		enabled         int
	}
	var records []modRecord

	for _, r := range regs {
		if len(r.Caps.Functions) == 0 {
			records = append(records, modRecord{r.Name, "", "", 1})
			continue
		}
		for _, f := range r.Caps.Functions {
			enabled := 1
			if val, ok := r.EnabledFunc[f]; ok && !val {
				enabled = 0
			}
			if len(r.Caps.InputTypes) == 0 {
				records = append(records, modRecord{r.Name, f, "", enabled})
				continue
			}
			for _, t := range r.Caps.InputTypes {
				records = append(records, modRecord{r.Name, f, t, enabled})
			}
		}
	}

	if len(records) > 0 {
		const batchSize = 240 // 4 fields * 240 < 999 parameter limit
		for i := 0; i < len(records); i += batchSize {
			end := i + batchSize
			if end > len(records) {
				end = len(records)
			}
			currentBatch := records[i:end]
			placeholders := make([]string, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*4)
			for j, r := range currentBatch {
				placeholders[j] = "(?, ?, ?, ?)"
				values = append(values, r.name, r.fn, r.itype, r.enabled)
			}
			query := fmt.Sprintf("INSERT INTO modules (module_name, function, input_type, is_enabled) VALUES %s", strings.Join(placeholders, ","))
			if _, err := db.ExecContext(ctx, query, values...); err != nil {
				return err
			}
		}
	}

	return nil
}

// FindProjects searches for projects and checks module support for a target type in the master database.
func FindProjects(ctx context.Context, targetType, targetValue string) (projects []schema.ProjectInfo, hasModules bool, hasActiveFuncs bool, err error) {
	dbPath := filepath.Join("storage", "base", "master.db")
	db, dbErr := sql.Open("sqlite", dbPath)
	if dbErr != nil {
		return nil, false, false, dbErr
	}
	defer func() {
		cerr := db.Close()
		if err == nil {
			err = cerr
		}
	}()

	// Find existing projects.
	queryProjects := `SELECT id, name, db_identifier, initial_target_type, initial_target_value, status, created_at
	                  FROM projects
	                  WHERE initial_target_type = ? AND initial_target_value = ? AND status = 'active'`
	rows, rErr := db.QueryContext(ctx, queryProjects, targetType, targetValue)
	if rErr != nil {
		return nil, false, false, rErr
	}
	defer func() {
		cerr := rows.Close()
		if err == nil {
			err = cerr
		}
	}()

	for rows.Next() {
		var p schema.ProjectInfo
		var createdAtStr string
		if sErr := rows.Scan(&p.ID, &p.Name, &p.DBIdentifier, &p.InitialTargetType, &p.InitialTargetValue, &p.Status, &createdAtStr); sErr != nil {
			return nil, false, false, sErr
		}
		layouts := []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05Z"}
		var parsedTime time.Time
		for _, layout := range layouts {
			if t, err := time.Parse(layout, createdAtStr); err == nil {
				parsedTime = t.Local()
				break
			}
		}
		p.CreatedAt = parsedTime
		p.DBIdentifier = AllocateWorkspaceRoute(p.DBIdentifier)
		projects = append(projects, p)
	}

	// Check for module support.
	var totalCount, enabledCount int
	queryTotal := `SELECT COUNT(*) FROM modules WHERE input_type = ?`
	if mErr := db.QueryRowContext(ctx, queryTotal, targetType).Scan(&totalCount); mErr != nil {
		return projects, false, false, mErr
	}

	queryEnabled := `SELECT COUNT(*) FROM modules WHERE input_type = ? AND is_enabled = 1`
	if mErr := db.QueryRowContext(ctx, queryEnabled, targetType).Scan(&enabledCount); mErr != nil {
		return projects, totalCount > 0, false, mErr
	}

	return projects, totalCount > 0, enabledCount > 0, nil
}

// CreateProjectDB creates a new project database and registers it in the master database.
func CreateProjectDB(ctx context.Context, targetType, targetValue string) (id string, err error) {
	projectsDir := filepath.Join("storage", "projects")
	if err := os.MkdirAll(projectsDir, 0750); err != nil {
		return "", err
	}

	uuidBytes := make([]byte, 16)
	if _, err := rand.Read(uuidBytes); err != nil {
		return "", err
	}
	uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40
	uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80
	projectID := "proj_" + hex.EncodeToString(uuidBytes)

	projectDBPath := filepath.Join(projectsDir, projectID+".db")
	db, dbErr := sql.Open("sqlite", projectDBPath)
	if dbErr != nil {
		return "", dbErr
	}
	defer func() {
		cerr := db.Close()
		if err == nil {
			err = cerr
		}
	}()

	schemas := []string{
		`CREATE TABLE entities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
                        value TEXT NOT NULL,
                        type TEXT NOT NULL,
			out_of_scope BOOLEAN DEFAULT FALSE,
			category TEXT NOT NULL DEFAULT 'node',
			UNIQUE(type, value)
		);`,
		`CREATE TABLE entity_tags (
			entity_id INTEGER NOT NULL REFERENCES entities(id),
			tag TEXT NOT NULL,
			UNIQUE(entity_id, tag)
		);`,
		`CREATE TABLE relations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_entity_id INTEGER NOT NULL REFERENCES entities(id),
			target_entity_id INTEGER NOT NULL REFERENCES entities(id),
			UNIQUE(source_entity_id, target_entity_id)
		);`,
		`CREATE TABLE raw_data (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			raw_data TEXT NOT NULL
		);`,
		`CREATE TABLE entity_function_log (
			entity_id INTEGER NOT NULL REFERENCES entities(id),
                        module_name TEXT NOT NULL,
			function_name TEXT NOT NULL,
			is_success BOOLEAN NOT NULL,
			id_raw_data INTEGER REFERENCES raw_data(id),
			UNIQUE(entity_id, module_name, function_name)
		);`,
		`CREATE TABLE observations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			relation_id INTEGER NOT NULL REFERENCES relations(id),
			module_name TEXT NOT NULL,
			function_name TEXT NOT NULL,
			context TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE errors (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_entity_id INTEGER NOT NULL REFERENCES entities(id),
			module_name TEXT NOT NULL,
			function_name TEXT NOT NULL,
			error_type TEXT NOT NULL,
			error_text TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
	}

	for _, s := range schemas {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return "", err
		}
	}

	// Insert the initial target entity
	if _, err := db.ExecContext(ctx, "INSERT INTO entities(type, value) VALUES(?, ?)", targetType, targetValue); err != nil {
		return "", err
	}

	masterDBPath := filepath.Join("storage", "base", "master.db")
	masterDB, mdbErr := sql.Open("sqlite", masterDBPath)
	if mdbErr != nil {
		return "", mdbErr
	}
	defer func() {
		cerr := masterDB.Close()
		if err == nil {
			err = cerr
		}
	}()

	insertProject := `INSERT INTO projects (name, db_identifier, initial_target_type, initial_target_value, status)
	                  VALUES (?, ?, ?, ?, ?)`
	if _, err := masterDB.ExecContext(ctx, insertProject, targetValue, projectID, targetType, targetValue, "active"); err != nil {
		return "", err
	}

	return AllocateWorkspaceRoute(projectID), nil
}

// Store saves incoming data to the project database and returns an updated entity list.
func Store(ctx context.Context, data *schema.ProcessorToRepoData) (resData *schema.RepoToDispatcherData, err error) {
	internalName, err := ResolveWorkspaceRoute(data.ProjectID)
	if err != nil {
		return nil, err
	}

	// Open the project-specific database
	dbPath := filepath.Join("storage", "projects", internalName+".db")
	db, dbErr := sql.Open("sqlite", dbPath)
	if dbErr != nil {
		return nil, dbErr
	}
	defer func() {
		cerr := db.Close()
		if err == nil {
			err = cerr
		}
	}()

	// Begin a transaction
	tx, txErr := db.BeginTx(ctx, nil)
	if txErr != nil {
		return nil, txErr
	}
	defer func() {
		rErr := tx.Rollback()
		if rErr != nil && !errors.Is(rErr, sql.ErrTxDone) {
			if err == nil {
				err = rErr
			}
		}
	}()

	// Collect all entities and resolve their IDs.
	entityMap := make(map[string]schema.Entity)
	scopeMap := make(map[string]bool)

	entityMap[fmt.Sprintf("%s:%s", data.SourceEntity.Type, data.SourceEntity.Value)] = data.SourceEntity
	for _, group := range data.Groups {
		srcKey := fmt.Sprintf("%s:%s", group.Source.Type, group.Source.Value)
		if _, exists := entityMap[srcKey]; !exists {
			entityMap[srcKey] = schema.Entity{Type: group.Source.Type, Value: group.Source.Value}
		}
		for _, res := range group.Results {
			key := fmt.Sprintf("%s:%s", res.Type, res.Value)
			entityMap[key] = schema.Entity{
				Type:     res.Type,
				Value:    res.Value,
				Category: res.Category,
				Tags:     res.Tags,
			}
			scopeMap[key] = res.OutOfScope
		}
	}

	entityMetaMap, err := upsertAndGetEntities(ctx, tx, entityMap, scopeMap)
	if err != nil {
		return nil, err
	}

	sourceKey := fmt.Sprintf("%s:%s", data.SourceEntity.Type, data.SourceEntity.Value)
	sourceID := entityMetaMap[sourceKey].id

	rawDataIDs := make(map[string]sql.NullInt64)
	for fn, rawData := range data.FunctionRawData {
		if rawData != "" {
			res, err := tx.ExecContext(ctx, "INSERT INTO raw_data (raw_data) VALUES (?)", rawData)
			if err != nil {
				return nil, err
			}
			id, err := res.LastInsertId()
			if err != nil {
				return nil, err
			}
			rawDataIDs[fn] = sql.NullInt64{Int64: id, Valid: true}
		} else {
			rawDataIDs[fn] = sql.NullInt64{Valid: false}
		}
	}

	type relationCtx struct {
		srcID int64
		res   schema.ProcessorToRepoValidResult
	}
	var flatRelations []relationCtx
	var flatResults []schema.ProcessorToRepoValidResult
	for _, group := range data.Groups {
		srcKey := fmt.Sprintf("%s:%s", group.Source.Type, group.Source.Value)
		sID := entityMetaMap[srcKey].id
		for _, res := range group.Results {
			flatRelations = append(flatRelations, relationCtx{srcID: sID, res: res})
			flatResults = append(flatResults, res)
		}
	}

	// Batch insert tags.
	type tagItem struct {
		eid int64
		tag string
	}
	var tagItems []tagItem
	for key, e := range entityMap {
		if len(e.Tags) > 0 {
			eid := entityMetaMap[key].id
			for _, t := range e.Tags {
				if t != "" {
					tagItems = append(tagItems, tagItem{eid: eid, tag: t})
				}
			}
		}
	}
	if len(tagItems) > 0 {
		const batchSize = 499 // 2 fields per row
		for i := 0; i < len(tagItems); i += batchSize {
			end := i + batchSize
			if end > len(tagItems) {
				end = len(tagItems)
			}
			currentBatch := tagItems[i:end]
			placeholders := make([]string, 0, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*2)
			for _, ti := range currentBatch {
				placeholders = append(placeholders, "(?, ?)")
				values = append(values, ti.eid, ti.tag)
			}
			query := fmt.Sprintf("INSERT OR IGNORE INTO entity_tags(entity_id, tag) VALUES %s", strings.Join(placeholders, ","))
			if _, err := tx.ExecContext(ctx, query, values...); err != nil {
				return nil, err
			}
		}
	}

	// Batch insert relations.
	if len(flatRelations) > 0 {
		const batchSize = 499 // 2 fields per row
		for i := 0; i < len(flatRelations); i += batchSize {
			end := i + batchSize
			if end > len(flatRelations) {
				end = len(flatRelations)
			}
			currentBatch := flatRelations[i:end]
			placeholders := make([]string, 0, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*2)
			for _, item := range currentBatch {
				targetKey := fmt.Sprintf("%s:%s", item.res.Type, item.res.Value)
				targetID := entityMetaMap[targetKey].id
				if targetID == item.srcID {
					continue
				}
				placeholders = append(placeholders, "(?, ?)")
				values = append(values, item.srcID, targetID)
			}
			if len(placeholders) > 0 {
				query := fmt.Sprintf("INSERT OR IGNORE INTO relations(source_entity_id, target_entity_id) VALUES %s", strings.Join(placeholders, ","))
				if _, err := tx.ExecContext(ctx, query, values...); err != nil {
					return nil, err
				}
			}
		}
	}

	// Batch retrieve relation IDs.
	type relKey struct {
		srcID int64
		tgtID int64
	}
	relationIDMap := make(map[relKey]int64)
	if len(flatRelations) > 0 {
		const batchSize = 499 // 2 fields * 499 < 999 parameter limit
		for i := 0; i < len(flatRelations); i += batchSize {
			end := i + batchSize
			if end > len(flatRelations) {
				end = len(flatRelations)
			}
			currentBatch := flatRelations[i:end]
			placeholders := make([]string, 0, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*2)
			foundAny := false
			for _, item := range currentBatch {
				targetKey := fmt.Sprintf("%s:%s", item.res.Type, item.res.Value)
				targetID := entityMetaMap[targetKey].id
				if targetID == item.srcID {
					continue
				}
				placeholders = append(placeholders, "(source_entity_id = ? AND target_entity_id = ?)")
				values = append(values, item.srcID, targetID)
				foundAny = true
			}
			if !foundAny {
				continue
			}
			query := fmt.Sprintf("SELECT id, source_entity_id, target_entity_id FROM relations WHERE %s", strings.Join(placeholders, " OR "))
			rows, err := tx.QueryContext(ctx, query, values...)
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var rid, sid, tid int64
				if err := rows.Scan(&rid, &sid, &tid); err != nil {
					if errClose := rows.Close(); errClose != nil {
						return nil, err
					}
					return nil, err
				}
				relationIDMap[relKey{srcID: sid, tgtID: tid}] = rid
			}
			if err := rows.Close(); err != nil {
				return nil, err
			}
		}
	}

	// Batch insert observations.
	if len(flatRelations) > 0 {
		const batchSize = 249 // 4 fields * 249 < 999 parameter limit
		for i := 0; i < len(flatRelations); i += batchSize {
			end := i + batchSize
			if end > len(flatRelations) {
				end = len(flatRelations)
			}
			currentBatch := flatRelations[i:end]
			placeholders := make([]string, 0, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*4)
			for _, item := range currentBatch {
				targetKey := fmt.Sprintf("%s:%s", item.res.Type, item.res.Value)
				targetID := entityMetaMap[targetKey].id
				if targetID == item.srcID {
					continue
				}
				relID := relationIDMap[relKey{srcID: item.srcID, tgtID: targetID}]
				placeholders = append(placeholders, "(?, ?, ?, ?)")
				values = append(values, relID, data.ModuleName, item.res.Function, item.res.Context)
			}
			if len(placeholders) > 0 {
				query := fmt.Sprintf("INSERT INTO observations(relation_id, module_name, function_name, context) VALUES %s", strings.Join(placeholders, ","))
				if _, err := tx.ExecContext(ctx, query, values...); err != nil {
					return nil, err
				}
			}
		}
	}

	// Batch insert errors.
	if len(data.Errors) > 0 {
		const batchSize = 199 // 5 fields per row
		for i := 0; i < len(data.Errors); i += batchSize {
			end := i + batchSize
			if end > len(data.Errors) {
				end = len(data.Errors)
			}
			currentBatch := data.Errors[i:end]
			placeholders := make([]string, 0, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*5)
			for _, e := range currentBatch {
				placeholders = append(placeholders, "(?, ?, ?, ?, ?)")
				values = append(values, sourceID, data.ModuleName, e.Function, e.ErrorType, e.ErrorText)
			}
			query := fmt.Sprintf("INSERT INTO errors(source_entity_id, module_name, function_name, error_type, error_text) VALUES %s", strings.Join(placeholders, ","))
			if _, err := tx.ExecContext(ctx, query, values...); err != nil {
				return nil, err
			}
		}
	}

	// Batch update entity function log.
	type logItem struct {
		eid       int64
		fn        string
		ok        int
		idRawData sql.NullInt64
	}
	logMap := make(map[string]logItem)

	addLog := func(eid int64, fn string, ok int, idRaw sql.NullInt64) {
		k := fmt.Sprintf("%d:%s", eid, fn)
		if existing, exists := logMap[k]; !exists || (!existing.idRawData.Valid && idRaw.Valid) {
			logMap[k] = logItem{eid: eid, fn: fn, ok: ok, idRawData: idRaw}
		}
	}

	for _, item := range flatRelations {
		idRaw := rawDataIDs[item.res.Function]
		addLog(sourceID, item.res.Function, 1, idRaw)
		addLog(item.srcID, item.res.Function, 1, idRaw)
		if item.res.Applied {
			targetKey := fmt.Sprintf("%s:%s", item.res.Type, item.res.Value)
			targetID := entityMetaMap[targetKey].id
			addLog(targetID, item.res.Function, 1, idRaw)
		}
	}
	for _, e := range data.Errors {
		addLog(sourceID, e.Function, 0, rawDataIDs[e.Function])
	}
	for _, fn := range data.FunctionsWithoutResults {
		addLog(sourceID, fn, 1, rawDataIDs[fn])
	}

	var logs []logItem
	for _, l := range logMap {
		logs = append(logs, l)
	}

	if len(logs) > 0 {
		const batchSize = 199 // 5 fields per row
		for i := 0; i < len(logs); i += batchSize {
			end := i + batchSize
			if end > len(logs) {
				end = len(logs)
			}
			currentBatch := logs[i:end]
			placeholders := make([]string, 0, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*5)
			for _, l := range currentBatch {
				placeholders = append(placeholders, "(?, ?, ?, ?, ?)")
				values = append(values, l.eid, data.ModuleName, l.fn, l.ok, l.idRawData)
			}
			query := fmt.Sprintf(`INSERT INTO entity_function_log(entity_id, module_name, function_name, is_success, id_raw_data)
			                      VALUES %s ON CONFLICT(entity_id, module_name, function_name)
			                      DO UPDATE SET is_success = excluded.is_success, id_raw_data = excluded.id_raw_data`, strings.Join(placeholders, ","))
			if _, err := tx.ExecContext(ctx, query, values...); err != nil {
				return nil, err
			}
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	var targets []entityWithID
	for _, res := range flatResults {
		key := fmt.Sprintf("%s:%s", res.Type, res.Value)
		meta := entityMetaMap[key]
		targets = append(targets, entityWithID{id: meta.id, e: schema.Entity{Type: res.Type, Value: res.Value}, outOfScope: meta.outOfScope})
	}

	batch, err := buildBatchItems(ctx, db, targets)
	if err != nil {
		return nil, err
	}

	if len(batch) == 0 {
		return nil, nil
	}

	return &schema.RepoToDispatcherData{ProjectID: data.ProjectID, Batch: batch}, nil
}

// upsertAndGetEntities inserts entities if they don't exist and returns a map of their IDs.
type entityMeta struct {
	id         int64
	outOfScope bool
}

func upsertAndGetEntities(ctx context.Context, tx *sql.Tx, entityMap map[string]schema.Entity, scopeMap map[string]bool) (map[string]entityMeta, error) {
	if len(entityMap) == 0 {
		return make(map[string]entityMeta), nil
	}

	entityList := make([]schema.Entity, 0, len(entityMap))
	for _, e := range entityMap {
		entityList = append(entityList, e)
	}

	const batchSize = 249 // SQLite parameter limit is 999, each entity has 4 fields (type, value, out_of_scope, category)

	// Batch insert entities.
	for i := 0; i < len(entityList); i += batchSize {
		end := i + batchSize
		if end > len(entityList) {
			end = len(entityList)
		}
		currentBatch := entityList[i:end]
		placeholders := make([]string, len(currentBatch))
		values := make([]interface{}, 0, len(currentBatch)*4)
		for j, entity := range currentBatch {
			placeholders[j] = "(?, ?, ?, ?)"
			key := fmt.Sprintf("%s:%s", entity.Type, entity.Value)
			values = append(values, entity.Type, entity.Value, scopeMap[key], entity.Category)
		}
		query := fmt.Sprintf(`INSERT INTO entities(type, value, out_of_scope, category) VALUES %s
		                      ON CONFLICT(type, value) DO UPDATE SET out_of_scope = out_of_scope OR excluded.out_of_scope, category = CASE WHEN excluded.category = '' THEN category ELSE excluded.category END`,
			strings.Join(placeholders, ","))
		if _, err := tx.ExecContext(ctx, query, values...); err != nil {
			return nil, err
		}
	}

	// Batch retrieve entity IDs.
	entityMetaMap := make(map[string]entityMeta)
	for i := 0; i < len(entityList); i += batchSize {
		end := i + batchSize
		if end > len(entityList) {
			end = len(entityList)
		}
		currentBatch := entityList[i:end]
		placeholders := make([]string, len(currentBatch))
		values := make([]interface{}, 0, len(currentBatch)*2)
		for j, entity := range currentBatch {
			placeholders[j] = "(type = ? AND value = ?)"
			values = append(values, entity.Type, entity.Value)
		}
		query := "SELECT id, type, value, out_of_scope, category FROM entities WHERE " + strings.Join(placeholders, " OR ")
		rows, err := tx.QueryContext(ctx, query, values...)
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var id int64
			var entType, entValue string
			var outOfScope bool
			var entCategory string
			if err := rows.Scan(&id, &entType, &entValue, &outOfScope, &entCategory); err != nil {
				if errClose := rows.Close(); errClose != nil {
					return nil, err
				}
				return nil, err
			}
			entityMetaMap[fmt.Sprintf("%s:%s", entType, entValue)] = entityMeta{id: id, outOfScope: outOfScope}
		}
		if err := rows.Err(); err != nil {
			if errClose := rows.Close(); errClose != nil {
				return nil, err
			}
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}

	return entityMetaMap, nil
}

// GetProjectStatus analyzes a project's state against available modules.
func GetProjectStatus(ctx context.Context, projectID string) (pending []schema.PendingTask, errors []string, err error) {
	internalName, err := ResolveWorkspaceRoute(projectID)
	if err != nil {
		return nil, nil, err
	}

	dbPath := filepath.Join("storage", "projects", internalName+".db")
	db, dbErr := sql.Open("sqlite", dbPath)
	if dbErr != nil {
		return nil, nil, dbErr
	}
	defer func() {
		cerr := db.Close()
		if err == nil {
			err = cerr
		}
	}()

	masterDBPath := filepath.Join("storage", "base", "master.db")
	// modernc/sqlite doesn't always support parameterized ATTACH, safe to format since path is controlled
	if _, err := db.ExecContext(ctx, fmt.Sprintf("ATTACH DATABASE '%s' AS master", masterDBPath)); err != nil {
		return nil, nil, err
	}

	pendingQuery := `
		SELECT DISTINCT m.module_name, m.function, e.type,
		       (SELECT GROUP_CONCAT(tag) FROM entity_tags WHERE entity_id = e.id) as tags
		FROM entities e
		JOIN master.modules m ON e.type = m.input_type
		LEFT JOIN entity_function_log efl
		  ON e.id = efl.entity_id AND m.module_name = efl.module_name AND m.function = efl.function_name
		WHERE efl.entity_id IS NULL AND m.function != '' AND e.out_of_scope = FALSE AND m.is_enabled = 1`

	rows, rErr := db.QueryContext(ctx, pendingQuery)
	if rErr != nil {
		return nil, nil, rErr
	}
	defer func() {
		cerr := rows.Close()
		if err == nil {
			err = cerr
		}
	}()

	for rows.Next() {
		var mod, fn, eType string
		var tagsStr sql.NullString
		if err := rows.Scan(&mod, &fn, &eType, &tagsStr); err == nil {
			var eTags []string
			if tagsStr.Valid && tagsStr.String != "" {
				eTags = strings.Split(tagsStr.String, ",")
			}
			pending = append(pending, schema.PendingTask{
				ModuleName: mod,
				Function:   fn,
				EntityType: eType,
				EntityTags: eTags,
			})
		}
	}
	errorQuery := `
		SELECT DISTINCT efl.module_name, efl.function_name
		FROM entity_function_log efl
		JOIN entities e ON e.id = efl.entity_id
		JOIN master.modules m ON efl.module_name = m.module_name AND efl.function_name = m.function
		WHERE efl.is_success = 0 AND e.out_of_scope = FALSE AND m.is_enabled = 1`
	rowsErr, reErr := db.QueryContext(ctx, errorQuery)
	if reErr != nil {
		return pending, nil, reErr
	}
	defer func() {
		cerr := rowsErr.Close()
		if err == nil {
			err = cerr
		}
	}()

	for rowsErr.Next() {
		var mod, fn string
		if err := rowsErr.Scan(&mod, &fn); err == nil {
			errors = append(errors, fmt.Sprintf("%s:%s", mod, fn))
		}
	}

	return pending, errors, nil
}

// ResetProjectLog clears execution logs for a project to force rescan.
func ResetProjectLog(ctx context.Context, projectID string, clearAll, clearErrors bool) (err error) {
	internalName, err := ResolveWorkspaceRoute(projectID)
	if err != nil {
		return err
	}

	dbPath := filepath.Join("storage", "projects", internalName+".db")
	db, dbErr := sql.Open("sqlite", dbPath)
	if dbErr != nil {
		return dbErr
	}
	defer func() {
		cerr := db.Close()
		if err == nil {
			err = cerr
		}
	}()

	masterDBPath := filepath.Join("storage", "base", "master.db")
	if _, err := db.ExecContext(ctx, fmt.Sprintf("ATTACH DATABASE '%s' AS master", masterDBPath)); err != nil {
		return err
	}

	if clearAll {
		query := `DELETE FROM entity_function_log
		          WHERE EXISTS (
		              SELECT 1 FROM master.modules m
		              WHERE m.module_name = entity_function_log.module_name
		                AND m.function = entity_function_log.function_name
		                AND m.is_enabled = 1
		          )`
		_, err = db.ExecContext(ctx, query)
	} else if clearErrors {
		query := `DELETE FROM entity_function_log
		          WHERE is_success = 0 AND EXISTS (
		              SELECT 1 FROM master.modules m
		              WHERE m.module_name = entity_function_log.module_name
		                AND m.function = entity_function_log.function_name
		                AND m.is_enabled = 1
		          )`
		_, err = db.ExecContext(ctx, query)
	}
	return err
}

// GetResumePayload queries the database for entities needing processing and constructs a dispatch batch.
func GetResumePayload(ctx context.Context, projectID string, resumePending, retryErrors bool) (resData *schema.RepoToDispatcherData, err error) {
	internalName, err := ResolveWorkspaceRoute(projectID)
	if err != nil {
		return nil, err
	}

	dbPath := filepath.Join("storage", "projects", internalName+".db")
	db, dbErr := sql.Open("sqlite", dbPath)
	if dbErr != nil {
		return nil, dbErr
	}
	defer func() {
		cerr := db.Close()
		if err == nil {
			err = cerr
		}
	}()

	masterDBPath := filepath.Join("storage", "base", "master.db")
	if _, err := db.ExecContext(ctx, fmt.Sprintf("ATTACH DATABASE '%s' AS master", masterDBPath)); err != nil {
		return nil, err
	}

	var queryParts []string
	if resumePending {
		queryParts = append(queryParts, `
			SELECT DISTINCT e.id, e.type, e.value, e.out_of_scope
			FROM entities e
			JOIN master.modules m ON e.type = m.input_type
			LEFT JOIN entity_function_log efl
			  ON e.id = efl.entity_id AND m.module_name = efl.module_name AND m.function = efl.function_name
			WHERE efl.entity_id IS NULL AND m.function != '' AND e.out_of_scope = FALSE AND m.is_enabled = 1`)
	}
	if retryErrors {
		queryParts = append(queryParts, `
			SELECT DISTINCT e.id, e.type, e.value, e.out_of_scope
			FROM entities e
			JOIN entity_function_log efl ON e.id = efl.entity_id
			JOIN master.modules m ON efl.module_name = m.module_name AND efl.function_name = m.function
			WHERE efl.is_success = 0 AND e.out_of_scope = FALSE AND m.is_enabled = 1`)
	}

	if len(queryParts) == 0 {
		return nil, nil
	}

	rows, rErr := db.QueryContext(ctx, strings.Join(queryParts, " UNION "))
	if rErr != nil {
		return nil, rErr
	}
	defer func() {
		cerr := rows.Close()
		if err == nil {
			err = cerr
		}
	}()

	var entities []entityWithID
	for rows.Next() {
		var id int64
		var t, v string
		var oos bool
		if sErr := rows.Scan(&id, &t, &v, &oos); sErr != nil {
			return nil, sErr
		}
		entities = append(entities, entityWithID{id: id, e: schema.Entity{Type: t, Value: v}, outOfScope: oos})
	}

	if retryErrors {
		if _, err := db.ExecContext(ctx, "DELETE FROM entity_function_log WHERE is_success = 0"); err != nil {
			return nil, err
		}
	}

	batch, err := buildBatchItems(ctx, db, entities)
	if err != nil {
		return nil, err
	}

	if len(batch) == 0 {
		return nil, nil
	}
	return &schema.RepoToDispatcherData{ProjectID: projectID, Batch: batch}, nil
}

type entityWithID struct {
	id         int64
	e          schema.Entity
	outOfScope bool
}

func buildBatchItems(ctx context.Context, db *sql.DB, entities []entityWithID) ([]schema.RepoToDispatcherBatchItem, error) {
	if len(entities) == 0 {
		return nil, nil
	}

	entityFunctions := make(map[int64][]schema.ModuleFunction)
	entityTags := make(map[int64][]string)
	const batchSize = 999

	for i := 0; i < len(entities); i += batchSize {
		end := i + batchSize
		if end > len(entities) {
			end = len(entities)
		}

		currentBatch := entities[i:end]
		placeholders := make([]string, len(currentBatch))
		args := make([]interface{}, len(currentBatch))
		for j, ent := range currentBatch {
			placeholders[j] = "?"
			args[j] = ent.id
		}

		inClause := strings.Join(placeholders, ",")

		queryFn := fmt.Sprintf("SELECT entity_id, module_name, function_name FROM entity_function_log WHERE entity_id IN (%s)", inClause)
		rowsFn, err := db.QueryContext(ctx, queryFn, args...)
		if err != nil {
			return nil, err
		}

		for rowsFn.Next() {
			var eid int64
			var mod, fn string
			if err := rowsFn.Scan(&eid, &mod, &fn); err != nil {
				if errClose := rowsFn.Close(); errClose != nil {
					return nil, err
				}
				return nil, err
			}
			entityFunctions[eid] = append(entityFunctions[eid], schema.ModuleFunction{
				ModuleName: mod,
				Function:   fn,
			})
		}
		if err := rowsFn.Close(); err != nil {
			return nil, err
		}
		if err := rowsFn.Err(); err != nil {
			return nil, err
		}

		queryTags := fmt.Sprintf("SELECT entity_id, tag FROM entity_tags WHERE entity_id IN (%s)", inClause)
		rowsTags, err := db.QueryContext(ctx, queryTags, args...)
		if err != nil {
			return nil, err
		}

		for rowsTags.Next() {
			var eid int64
			var tag string
			if err := rowsTags.Scan(&eid, &tag); err != nil {
				if errClose := rowsTags.Close(); errClose != nil {
					return nil, err
				}
				return nil, err
			}
			entityTags[eid] = append(entityTags[eid], tag)
		}
		if err := rowsTags.Close(); err != nil {
			return nil, err
		}
		if err := rowsTags.Err(); err != nil {
			return nil, err
		}
	}

	batch := make([]schema.RepoToDispatcherBatchItem, 0, len(entities))
	for _, ent := range entities {
		e := ent.e
		e.Tags = entityTags[ent.id]
		batch = append(batch, schema.RepoToDispatcherBatchItem{
			Entity:             e,
			OutOfScope:         ent.outOfScope,
			CompletedFunctions: entityFunctions[ent.id],
		})
	}
	return batch, nil
}

// GetProjectStats retrieves the counts of unique entity values grouped by type.
func GetProjectStats(ctx context.Context, projectID string) (map[string]int, error) {
	internalName, err := ResolveWorkspaceRoute(projectID)
	if err != nil {
		return nil, err
	}

	dbPath := filepath.Join("storage", "projects", internalName+".db")
	db, dbErr := sql.Open("sqlite", dbPath)
	if dbErr != nil {
		return nil, dbErr
	}
	defer func() {
		cerr := db.Close()
		if err == nil {
			err = cerr
		}
	}()

	query := "SELECT type, COUNT(DISTINCT value) FROM entities WHERE out_of_scope = FALSE GROUP BY type"
	rows, rErr := db.QueryContext(ctx, query)
	if rErr != nil {
		return nil, rErr
	}
	defer func() {
		cerr := rows.Close()
		if err == nil {
			err = cerr
		}
	}()

	stats := make(map[string]int)
	for rows.Next() {
		var t string
		var c int
		if err := rows.Scan(&t, &c); err == nil {
			stats[t] = c
		}
	}

	return stats, nil
}

// GetGraphData retrieves all entities and their relations from the project database.
func GetGraphData(ctx context.Context, projectID string, includeRawData bool) (graph *schema.ProjectGraph, err error) {
	internalName, err := ResolveWorkspaceRoute(projectID)
	if err != nil {
		return nil, err
	}

	masterDBPath := filepath.Join("storage", "base", "master.db")
	masterDB, mdbErr := sql.Open("sqlite", masterDBPath)
	if mdbErr != nil {
		return nil, mdbErr
	}
	defer func() {
		cerr := masterDB.Close()
		if err == nil {
			err = cerr
		}
	}()

	var projectName, initialTarget string
	if mErr := masterDB.QueryRowContext(ctx, "SELECT name, initial_target_value FROM projects WHERE db_identifier = ?", internalName).Scan(&projectName, &initialTarget); mErr != nil {
		projectName = internalName
	}

	dbPath := filepath.Join("storage", "projects", internalName+".db")
	db, dbErr := sql.Open("sqlite", dbPath)
	if dbErr != nil {
		return nil, dbErr
	}
	defer func() {
		cerr := db.Close()
		if err == nil {
			err = cerr
		}
	}()

	query := `
		SELECT
			e1.type, e1.value, e1.category,
			e2.type, e2.value, e2.out_of_scope, e2.category,
			o.module_name, o.function_name, o.context, o.created_at, e1.id
		FROM relations r
		JOIN entities e1 ON r.source_entity_id = e1.id
		JOIN entities e2 ON r.target_entity_id = e2.id
		JOIN observations o ON r.id = o.relation_id
	`
	rows, rErr := db.QueryContext(ctx, query)
	if rErr != nil {
		return nil, rErr
	}
	defer func() {
		cerr := rows.Close()
		if err == nil {
			err = cerr
		}
	}()

	type edgeWithID struct {
		edge     schema.GraphEdge
		sourceID int64
	}
	var tempEdges []edgeWithID

	type rawDataKey struct {
		entityID   int64
		moduleName string
		funcName   string
	}
	neededRawData := make(map[rawDataKey]bool)

	for rows.Next() {
		var e schema.GraphEdge
		var sourceID int64
		err := rows.Scan(
			&e.Source.Type, &e.Source.Value, &e.Source.Category,
			&e.Target.Type, &e.Target.Value, &e.TargetOutOfScope, &e.Target.Category,
			&e.ModuleName, &e.FunctionName,
			&e.Context,
			&e.CreatedAt,
			&sourceID,
		)
		if err == nil {
			tempEdges = append(tempEdges, edgeWithID{edge: e, sourceID: sourceID})
			if includeRawData {
				neededRawData[rawDataKey{sourceID, e.ModuleName, e.FunctionName}] = true
			}
		}
	}

	if includeRawData && len(neededRawData) > 0 {
		rawMap := make(map[rawDataKey]string)
		rawQuery := `SELECT l.entity_id, l.module_name, l.function_name, r.raw_data
		             FROM entity_function_log l
		             JOIN raw_data r ON l.id_raw_data = r.id
		             WHERE l.id_raw_data IS NOT NULL`
		rawRows, rrErr := db.QueryContext(ctx, rawQuery)
		if rrErr == nil {
			for rawRows.Next() {
				var k rawDataKey
				var rd string
				if err := rawRows.Scan(&k.entityID, &k.moduleName, &k.funcName, &rd); err == nil {
					if neededRawData[k] {
						rawMap[k] = rd
					}
				}
			}
			if err := rawRows.Close(); err != nil {
				return nil, err
			}
		}

		for i, te := range tempEdges {
			k := rawDataKey{te.sourceID, te.edge.ModuleName, te.edge.FunctionName}
			if rd, ok := rawMap[k]; ok {
				tempEdges[i].edge.RawData = rd
			}
		}
	}

	var edges []schema.GraphEdge
	for _, te := range tempEdges {
		edges = append(edges, te.edge)
	}

	return &schema.ProjectGraph{
		ProjectName:   projectName,
		InitialTarget: initialTarget,
		Edges:         edges,
	}, nil
}
