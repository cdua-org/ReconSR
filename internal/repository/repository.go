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
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	AnchorEntityType   = "domain"
	StorageBaseDir     = "storage/base"
	StorageProjectsDir = "storage/projects"
	MasterDBName       = "master.db"
	sqliteMaxParams    = 999
)

type routeRegistry struct {
	mu     sync.RWMutex
	routes map[string]string
}

var activeRoutes = &routeRegistry{
	routes: make(map[string]string),
}

func generateRouteRef() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// AllocateWorkspaceRoute reserves a new route for the workspace context.
func AllocateWorkspaceRoute(internalName string) (string, error) {
	activeRoutes.mu.Lock()
	defer activeRoutes.mu.Unlock()

	ref, err := generateRouteRef()
	if err != nil {
		return "", err
	}
	activeRoutes.routes[ref] = internalName
	return ref, nil
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
	if err := os.MkdirAll(StorageBaseDir, 0750); err != nil {
		return err
	}

	dbPath := filepath.Join(StorageBaseDir, MasterDBName)
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
	dbPath := filepath.Join(StorageBaseDir, MasterDBName)
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
		ref, err := AllocateWorkspaceRoute(p.DBIdentifier)
		if err != nil {
			return nil, false, false, err
		}
		p.DBIdentifier = ref
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
func CreateProjectDB(ctx context.Context, targetType, targetValue, anchor string) (id string, err error) {
	if err := os.MkdirAll(StorageProjectsDir, 0750); err != nil {
		return "", err
	}

	uuidBytes := make([]byte, 16)
	if _, err := rand.Read(uuidBytes); err != nil {
		return "", err
	}
	uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40
	uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80
	projectID := "proj_" + hex.EncodeToString(uuidBytes)

	projectDBPath := filepath.Join(StorageProjectsDir, projectID+".db")
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
		`CREATE TABLE dictionary (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			value TEXT UNIQUE NOT NULL
		);`,
		`CREATE TABLE entities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			value_id INTEGER NOT NULL REFERENCES dictionary(id),
			out_of_scope BOOLEAN DEFAULT FALSE,
			category TEXT NOT NULL DEFAULT 'node',
			depth_strict INTEGER DEFAULT 0,
			depth_relaxed INTEGER DEFAULT 0,
			is_anchor BOOLEAN DEFAULT 0,
			anchor_id INTEGER REFERENCES entities(id),
			parent_id INTEGER REFERENCES entities(id)
		);`,
		`CREATE UNIQUE INDEX idx_entities_node ON entities(type, value_id) WHERE category = 'node';`,
		`CREATE UNIQUE INDEX idx_entities_property ON entities(type, value_id, parent_id) WHERE category = 'property';`,
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

	// Create anchor if applicable
	if anchor != "" {
		insertDictAnchor := `INSERT OR IGNORE INTO dictionary (value) VALUES (?)`
		if _, err := db.ExecContext(ctx, insertDictAnchor, anchor); err != nil {
			return "", err
		}
		insertAnchor := `INSERT INTO entities (type, value_id, category, is_anchor, depth_strict, depth_relaxed)
		                 VALUES ('domain', (SELECT id FROM dictionary WHERE value=?), 'node', 1, 999999, 0)
		                 ON CONFLICT(type, value_id) WHERE category = 'node' DO NOTHING`
		if _, err := db.ExecContext(ctx, insertAnchor, anchor); err != nil {
			return "", err
		}
	}

	// Insert the initial target entity
	insertDictTarget := `INSERT OR IGNORE INTO dictionary (value) VALUES (?)`
	if _, err := db.ExecContext(ctx, insertDictTarget, targetValue); err != nil {
		return "", err
	}

	insertTarget := `INSERT INTO entities (type, value_id, category, is_anchor, depth_strict, depth_relaxed, anchor_id)
	                 VALUES (?, (SELECT id FROM dictionary WHERE value=?), 'node', 0, 0, 0, (SELECT id FROM entities WHERE type='domain' AND value_id=(SELECT id FROM dictionary WHERE value=?)))
	                 ON CONFLICT(type, value_id) WHERE category = 'node' DO UPDATE SET
	                     category = excluded.category,
	                     is_anchor = 0,
	                     depth_strict = 0,
	                     depth_relaxed = 0,
	                     anchor_id = excluded.anchor_id`
	if _, err := db.ExecContext(ctx, insertTarget, targetType, targetValue, anchor); err != nil {
		return "", err
	}

	masterDBPath := filepath.Join(StorageBaseDir, MasterDBName)
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

	return AllocateWorkspaceRoute(projectID)
}

const unresolvedDepth = 999999

type batchEntityID uint32

type nodeKey struct {
	entityType string
	value      string
}

type propertyKey struct {
	parentID   batchEntityID
	entityType string
	value      string
}

type entityFields struct {
	entityType string
	value      string
	category   string
}

type batchBuildHints struct {
	itemCap     int
	nodeCap     int
	propertyCap int
	resultCap   int
}

type batchEntity struct {
	sourceID   batchEntityID
	parentID   batchEntityID
	entity     entityFields
	anchor     string
	outOfScope bool
	tags       []string
}

type batchResult struct {
	sourceID batchEntityID
	targetID batchEntityID
	result   schema.ProcessorToRepoValidResult
}

type storeBatch struct {
	rootID        batchEntityID
	entities      []batchEntity
	nodeIndex     map[nodeKey]batchEntityID
	nodeIDs       []batchEntityID
	propertyIndex map[propertyKey]batchEntityID
	propertyRefs  map[string][]batchEntityID
	propertyIDs   []batchEntityID
	results       []batchResult
	localIDMap    map[int]batchEntityID
}

type entityAgg struct {
	entity       schema.Entity
	outOfScope   bool
	depthStrict  int
	depthRelaxed int
	anchor       string
	isAnchor     bool
}

type entityMeta struct {
	id           int64
	outOfScope   bool
	depthStrict  int
	depthRelaxed int
}

type storedEntity struct {
	id           int64
	entity       entityFields
	outOfScope   bool
	depthStrict  int
	depthRelaxed int
	anchor       string
	isAnchor     bool
}

type entityState struct {
	dbID         int64
	outOfScope   bool
	depthStrict  int
	depthRelaxed int
	anchor       string
	isAnchor     bool
}

func entityKey(entityType, value string) string {
	return entityType + ":" + value
}

func normalizeCategory(category string) string {
	if category == "" {
		return "node"
	}
	return category
}

func estimateBatchBuildHints(data *schema.ProcessorToRepoData) batchBuildHints {
	hints := batchBuildHints{
		itemCap:   1,
		nodeCap:   1,
		resultCap: 1,
	}
	if data == nil {
		return hints
	}

	for _, group := range data.Groups {
		hints.resultCap += len(group.Results)
		for _, result := range group.Results {
			if normalizeCategory(result.Category) == "node" {
				hints.nodeCap++
			} else {
				hints.propertyCap++
			}
			if result.Anchor != "" {
				hints.nodeCap++
			}
		}
	}

	hints.itemCap += hints.nodeCap + hints.propertyCap
	return hints
}

func newStoreBatch(hints batchBuildHints) storeBatch {
	return storeBatch{
		entities:      make([]batchEntity, 0, hints.itemCap),
		nodeIndex:     make(map[nodeKey]batchEntityID, hints.nodeCap),
		nodeIDs:       make([]batchEntityID, 0, hints.nodeCap),
		propertyIndex: make(map[propertyKey]batchEntityID, hints.propertyCap),
		propertyRefs:  make(map[string][]batchEntityID, hints.propertyCap),
		propertyIDs:   make([]batchEntityID, 0, hints.propertyCap),
		results:       make([]batchResult, 0, hints.resultCap),
		localIDMap:    make(map[int]batchEntityID),
	}
}

func batchEntityOffset(id batchEntityID) int {
	return int(id - 1)
}

func (b *storeBatch) appendEntity(entity batchEntity) batchEntityID {
	b.entities = append(b.entities, entity)
	return batchEntityID(len(b.entities))
}

func (b *storeBatch) item(id batchEntityID) *batchEntity {
	return &b.entities[batchEntityOffset(id)]
}

func appendUniqueTags(dst []string, src []string) []string {
	for _, tag := range src {
		if tag == "" {
			continue
		}
		found := false
		for _, existing := range dst {
			if existing == tag {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, tag)
		}
	}
	return dst
}

func (b *storeBatch) addNode(entityType, value, category string, localID int) batchEntityID {
	key := nodeKey{entityType: entityType, value: value}
	if id, ok := b.nodeIndex[key]; ok {
		if category != "" {
			b.item(id).entity.category = category
		}
		if localID != 0 {
			b.localIDMap[localID] = id
		}
		return id
	}

	id := b.appendEntity(batchEntity{
		entity: entityFields{
			entityType: entityType,
			value:      value,
			category:   category,
		},
	})
	b.nodeIndex[key] = id
	b.nodeIDs = append(b.nodeIDs, id)
	if localID != 0 {
		b.localIDMap[localID] = id
	}
	return id
}

func (b *storeBatch) addProperty(sourceID, parentID batchEntityID, result schema.ProcessorToRepoValidResult) batchEntityID {
	key := propertyKey{parentID: parentID, entityType: result.Type, value: result.Value}
	if id, ok := b.propertyIndex[key]; ok {
		item := b.item(id)
		item.outOfScope = item.outOfScope || result.OutOfScope
		item.tags = appendUniqueTags(item.tags, result.Tags)
		if item.anchor == "" && result.Anchor != "" {
			item.anchor = result.Anchor
		}
		if result.LocalID != 0 {
			b.localIDMap[result.LocalID] = id
		}
		return id
	}

	id := b.appendEntity(batchEntity{
		sourceID:   sourceID,
		parentID:   parentID,
		entity:     entityFields{entityType: result.Type, value: result.Value, category: normalizeCategory(result.Category)},
		anchor:     result.Anchor,
		outOfScope: result.OutOfScope,
		tags:       appendUniqueTags(nil, result.Tags),
	})
	b.propertyIndex[key] = id
	b.propertyRefs[entityKey(result.Type, result.Value)] = append(b.propertyRefs[entityKey(result.Type, result.Value)], id)
	b.propertyIDs = append(b.propertyIDs, id)
	if result.LocalID != 0 {
		b.localIDMap[result.LocalID] = id
	}
	return id
}

func (b *storeBatch) resolveSource(rootKey string, source schema.EntityRef) (batchEntityID, bool, error) {
	if source.LocalID != 0 {
		if id, ok := b.localIDMap[source.LocalID]; ok {
			return id, true, nil
		}
		return 0, false, nil
	}

	key := entityKey(source.Type, source.Value)
	if key == rootKey {
		return b.rootID, true, nil
	}

	if id, ok := b.nodeIndex[nodeKey{entityType: source.Type, value: source.Value}]; ok {
		return id, true, nil
	}

	propertyIDs := b.propertyRefs[key]
	if len(propertyIDs) == 0 {
		return 0, false, nil
	}
	if len(propertyIDs) == 1 {
		return propertyIDs[0], true, nil
	}
	return 0, false, errors.New("batch source is ambiguous")
}

func buildStoreBatch(data *schema.ProcessorToRepoData, source entityFields) (storeBatch, error) {
	hints := estimateBatchBuildHints(data)
	batch := newStoreBatch(hints)
	if source.category == "property" {
		batch.rootID = batch.appendEntity(batchEntity{entity: source})
	} else {
		batch.rootID = batch.addNode(source.entityType, source.value, source.category, 0)
	}

	rootKey := entityKey(source.entityType, source.value)
	pending := make([]schema.ResultGroup, len(data.Groups))
	copy(pending, data.Groups)
	for len(pending) > 0 {
		progressed := false
		nextPending := make([]schema.ResultGroup, 0, len(pending))
		for _, group := range pending {
			sourceID, resolved, err := batch.resolveSource(rootKey, group.Source)
			if err != nil {
				return storeBatch{}, err
			}
			if !resolved {
				nextPending = append(nextPending, group)
				continue
			}

			for _, result := range group.Results {
				category := normalizeCategory(result.Category)
				var targetID batchEntityID
				if category == "node" {
					targetID = batch.addNode(result.Type, result.Value, category, result.LocalID)
				} else {
					targetID = batch.addProperty(sourceID, sourceID, result)
				}
				if result.Anchor != "" {
					batch.addNode(AnchorEntityType, result.Anchor, "node", 0)
				}
				batch.results = append(batch.results, batchResult{sourceID: sourceID, targetID: targetID, result: result})
			}
			progressed = true
		}
		if !progressed {
			return storeBatch{}, errors.New("batch source could not be resolved")
		}
		pending = nextPending
	}

	return batch, nil
}

func (b *storeBatch) pendingProperties() map[batchEntityID]struct{} {
	pending := make(map[batchEntityID]struct{}, len(b.propertyIDs))
	for _, id := range b.propertyIDs {
		pending[id] = struct{}{}
	}
	return pending
}

func nextResolvedPropertyLayer(batch *storeBatch, pending map[batchEntityID]struct{}, resolved map[batchEntityID]int64) []batchEntityID {
	layer := make([]batchEntityID, 0, len(pending))
	for id := range pending {
		if _, ok := resolved[batch.item(id).parentID]; !ok {
			continue
		}
		layer = append(layer, id)
		delete(pending, id)
	}
	return layer
}

func loadStoredEntity(ctx context.Context, tx *sql.Tx, entityID int64) (storedEntity, error) {
	var entity storedEntity
	var anchorValue sql.NullString
	query := `SELECT e.id, e.type, d.value, e.category, e.out_of_scope, e.depth_strict,
	                 COALESCE(a.depth_relaxed, e.depth_relaxed), e.is_anchor, ad.value
	          FROM entities e
	          JOIN dictionary d ON e.value_id = d.id
	          LEFT JOIN entities a ON e.anchor_id = a.id
	          LEFT JOIN dictionary ad ON a.value_id = ad.id
	          WHERE e.id = ?`
	if err := tx.QueryRowContext(ctx, query, entityID).Scan(
		&entity.id,
		&entity.entity.entityType,
		&entity.entity.value,
		&entity.entity.category,
		&entity.outOfScope,
		&entity.depthStrict,
		&entity.depthRelaxed,
		&entity.isAnchor,
		&anchorValue,
	); err != nil {
		return storedEntity{}, err
	}
	entity.entity.category = normalizeCategory(entity.entity.category)
	if anchorValue.Valid {
		entity.anchor = anchorValue.String
	}
	return entity, nil
}

func collectBatchValues(batch *storeBatch) map[string]struct{} {
	values := make(map[string]struct{}, len(batch.entities))
	for i := range batch.entities {
		if batch.entities[i].entity.value != "" {
			values[batch.entities[i].entity.value] = struct{}{}
		}
	}
	return values
}

func upsertDictionaryIDs(ctx context.Context, tx *sql.Tx, values map[string]struct{}) (map[string]int64, error) {
	ids := make(map[string]int64, len(values))
	if len(values) == 0 {
		return ids, nil
	}

	items := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			items = append(items, value)
		}
	}
	if len(items) == 0 {
		return ids, nil
	}

	const batchSize = sqliteMaxParams // 1 field per row, capped at the SQLite parameter limit
	for i := 0; i < len(items); i += batchSize {
		end := i + batchSize
		if end > len(items) {
			end = len(items)
		}

		currentBatch := items[i:end]
		placeholders := make([]string, len(currentBatch))
		args := make([]interface{}, len(currentBatch))
		for j, value := range currentBatch {
			placeholders[j] = "(?)"
			args[j] = value
		}

		query := fmt.Sprintf(`INSERT INTO dictionary(value) VALUES %s
		                      ON CONFLICT(value) DO UPDATE SET value = excluded.value
		                      RETURNING id, value`, strings.Join(placeholders, ","))
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id int64
			var value string
			if err := rows.Scan(&id, &value); err != nil {
				if closeErr := rows.Close(); closeErr != nil {
					return nil, err
				}
				return nil, err
			}
			ids[value] = id
		}
		if err := rows.Err(); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return nil, err
			}
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}

	return ids, nil
}

func loadNodeStates(ctx context.Context, tx *sql.Tx, batch *storeBatch, states []entityState) error {
	if len(batch.nodeIDs) == 0 {
		return nil
	}

	const batchSize = sqliteMaxParams / 2 // 2 fields per lookup pair, 450 * 2 < 999 SQLite parameter limit
	for i := 0; i < len(batch.nodeIDs); i += batchSize {
		end := i + batchSize
		if end > len(batch.nodeIDs) {
			end = len(batch.nodeIDs)
		}

		currentBatch := batch.nodeIDs[i:end]
		placeholders := make([]string, len(currentBatch))
		args := make([]interface{}, 0, len(currentBatch)*2)
		for j, id := range currentBatch {
			item := batch.item(id)
			placeholders[j] = "(e.type = ? AND d.value = ?)"
			args = append(args, item.entity.entityType, item.entity.value)
		}

		query := `SELECT e.id, e.type, d.value, e.out_of_scope, e.depth_strict,
		                 COALESCE(a.depth_relaxed, e.depth_relaxed), e.is_anchor, ad.value
		          FROM entities e
		          JOIN dictionary d ON e.value_id = d.id
		          LEFT JOIN entities a ON e.anchor_id = a.id
		          LEFT JOIN dictionary ad ON a.value_id = ad.id
		          WHERE e.category = 'node' AND (` + strings.Join(placeholders, " OR ") + `)`
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var entityType string
			var value string
			var outOfScope bool
			var depthStrict int
			var depthRelaxed int
			var isAnchor bool
			var anchorValue sql.NullString
			if err := rows.Scan(&id, &entityType, &value, &outOfScope, &depthStrict, &depthRelaxed, &isAnchor, &anchorValue); err != nil {
				if closeErr := rows.Close(); closeErr != nil {
					return err
				}
				return err
			}
			tempID := batch.nodeIndex[nodeKey{entityType: entityType, value: value}]
			state := &states[tempID]
			state.dbID = id
			state.outOfScope = outOfScope
			state.depthStrict = depthStrict
			state.depthRelaxed = depthRelaxed
			state.isAnchor = isAnchor
			if anchorValue.Valid {
				state.anchor = anchorValue.String
			}
		}
		if err := rows.Err(); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return err
			}
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}

	return nil
}

func upsertAnchorNodes(ctx context.Context, tx *sql.Tx, batch *storeBatch, ids []batchEntityID, states []entityState, dictIDs map[string]int64, resolved map[batchEntityID]int64) error {
	if len(ids) == 0 {
		return nil
	}

	type rowKey struct {
		entityType string
		valueID    int64
	}

	const batchSize = sqliteMaxParams / 8 // 8 fields per row, 124 * 8 < 999 SQLite parameter limit
	for i := 0; i < len(ids); i += batchSize {
		end := i + batchSize
		if end > len(ids) {
			end = len(ids)
		}

		currentBatch := ids[i:end]
		placeholders := make([]string, len(currentBatch))
		values := make([]interface{}, 0, len(currentBatch)*8)
		batchIndex := make(map[rowKey]batchEntityID, len(currentBatch))
		for j, id := range currentBatch {
			item := batch.item(id)
			valueID := dictIDs[item.entity.value]
			batchIndex[rowKey{entityType: item.entity.entityType, valueID: valueID}] = id
			placeholders[j] = "(?, ?, ?, ?, ?, ?, ?, ?)"
			values = append(values, item.entity.entityType, valueID, states[id].outOfScope, item.entity.category, 1, states[id].depthStrict, states[id].depthRelaxed, nil)
		}

		query := fmt.Sprintf(`INSERT INTO entities(type, value_id, out_of_scope, category, is_anchor, depth_strict, depth_relaxed, anchor_id) VALUES %s
		                      ON CONFLICT(type, value_id) WHERE category = 'node' DO UPDATE SET
		                        out_of_scope = out_of_scope OR excluded.out_of_scope,
		                        category = excluded.category,
		                        is_anchor = MAX(is_anchor, excluded.is_anchor),
		                        depth_strict = MIN(depth_strict, excluded.depth_strict),
		                        depth_relaxed = MIN(depth_relaxed, excluded.depth_relaxed)
		                      RETURNING id, type, value_id`, strings.Join(placeholders, ","))
		rows, err := tx.QueryContext(ctx, query, values...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var dbID int64
			var entityType string
			var valueID int64
			if err := rows.Scan(&dbID, &entityType, &valueID); err != nil {
				if closeErr := rows.Close(); closeErr != nil {
					return err
				}
				return err
			}
			tempID := batchIndex[rowKey{entityType: entityType, valueID: valueID}]
			resolved[tempID] = dbID
			states[tempID].dbID = dbID
		}
		if err := rows.Err(); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return err
			}
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}

	return nil
}

func upsertRegularNodes(ctx context.Context, tx *sql.Tx, batch *storeBatch, ids []batchEntityID, states []entityState, dictIDs map[string]int64, resolved map[batchEntityID]int64) error {
	if len(ids) == 0 {
		return nil
	}

	type rowKey struct {
		entityType string
		valueID    int64
	}

	const batchSize = sqliteMaxParams / 8 // 8 fields per row, 124 * 8 < 999 SQLite parameter limit
	for i := 0; i < len(ids); i += batchSize {
		end := i + batchSize
		if end > len(ids) {
			end = len(ids)
		}

		currentBatch := ids[i:end]
		placeholders := make([]string, len(currentBatch))
		values := make([]interface{}, 0, len(currentBatch)*8)
		batchIndex := make(map[rowKey]batchEntityID, len(currentBatch))
		for j, id := range currentBatch {
			item := batch.item(id)
			valueID := dictIDs[item.entity.value]
			batchIndex[rowKey{entityType: item.entity.entityType, valueID: valueID}] = id

			var anchorID interface{}
			if states[id].anchor != "" {
				if anchorTempID, ok := batch.nodeIndex[nodeKey{entityType: AnchorEntityType, value: states[id].anchor}]; ok {
					if anchorDBID, ok := resolved[anchorTempID]; ok {
						anchorID = anchorDBID
					}
				}
			}

			placeholders[j] = "(?, ?, ?, ?, ?, ?, ?, ?)"
			values = append(values, item.entity.entityType, valueID, states[id].outOfScope, item.entity.category, 0, states[id].depthStrict, states[id].depthRelaxed, anchorID)
		}

		query := fmt.Sprintf(`INSERT INTO entities(type, value_id, out_of_scope, category, is_anchor, depth_strict, depth_relaxed, anchor_id) VALUES %s
		                      ON CONFLICT(type, value_id) WHERE category = 'node' DO UPDATE SET
		                        out_of_scope = out_of_scope OR excluded.out_of_scope,
		                        category = excluded.category,
		                        is_anchor = MIN(is_anchor, excluded.is_anchor),
		                        depth_strict = MIN(depth_strict, excluded.depth_strict),
		                        depth_relaxed = MIN(depth_relaxed, excluded.depth_relaxed),
		                        anchor_id = COALESCE(excluded.anchor_id, anchor_id)
		                      RETURNING id, type, value_id`, strings.Join(placeholders, ","))
		rows, err := tx.QueryContext(ctx, query, values...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var dbID int64
			var entityType string
			var valueID int64
			if err := rows.Scan(&dbID, &entityType, &valueID); err != nil {
				if closeErr := rows.Close(); closeErr != nil {
					return err
				}
				return err
			}
			tempID := batchIndex[rowKey{entityType: entityType, valueID: valueID}]
			resolved[tempID] = dbID
			states[tempID].dbID = dbID
		}
		if err := rows.Err(); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return err
			}
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}

	return nil
}

func syncNodeAnchors(ctx context.Context, tx *sql.Tx, batch *storeBatch, ids []batchEntityID, states []entityState, resolved map[batchEntityID]int64) error {
	updates := make([]struct {
		nodeID   int64
		anchorID int64
	}, 0, len(ids))
	for _, id := range ids {
		if states[id].anchor == "" {
			continue
		}
		anchorTempID, ok := batch.nodeIndex[nodeKey{entityType: AnchorEntityType, value: states[id].anchor}]
		if !ok {
			continue
		}
		nodeDBID, ok := resolved[id]
		if !ok {
			continue
		}
		anchorDBID, ok := resolved[anchorTempID]
		if !ok {
			continue
		}
		updates = append(updates, struct {
			nodeID   int64
			anchorID int64
		}{nodeID: nodeDBID, anchorID: anchorDBID})
	}
	if len(updates) == 0 {
		return nil
	}

	const batchSize = sqliteMaxParams / 3 // 3 fields per row, 333 * 3 < 999 SQLite parameter limit
	for i := 0; i < len(updates); i += batchSize {
		end := i + batchSize
		if end > len(updates) {
			end = len(updates)
		}

		currentBatch := updates[i:end]
		cases := make([]string, 0, len(currentBatch))
		whereIn := make([]string, 0, len(currentBatch))
		values := make([]interface{}, 0, len(currentBatch)*3)
		for _, item := range currentBatch {
			cases = append(cases, "WHEN ? THEN ?")
			values = append(values, item.nodeID, item.anchorID)
			whereIn = append(whereIn, "?")
		}
		for _, item := range currentBatch {
			values = append(values, item.nodeID)
		}

		query := fmt.Sprintf(`UPDATE entities
		                      SET anchor_id = CASE id %s ELSE anchor_id END
		                      WHERE id IN (%s)`, strings.Join(cases, " "), strings.Join(whereIn, ","))
		if _, err := tx.ExecContext(ctx, query, values...); err != nil {
			return err
		}
	}

	return nil
}

func upsertPropertyLayer(ctx context.Context, tx *sql.Tx, batch *storeBatch, ids []batchEntityID, states []entityState, dictIDs map[string]int64, resolved map[batchEntityID]int64) error {
	if len(ids) == 0 {
		return nil
	}

	type rowKey struct {
		entityType string
		valueID    int64
		parentID   int64
	}

	const batchSize = sqliteMaxParams / 8 // 8 fields per row, 124 * 8 < 999 SQLite parameter limit
	for i := 0; i < len(ids); i += batchSize {
		end := i + batchSize
		if end > len(ids) {
			end = len(ids)
		}

		currentBatch := ids[i:end]
		placeholders := make([]string, len(currentBatch))
		values := make([]interface{}, 0, len(currentBatch)*8)
		batchIndex := make(map[rowKey]batchEntityID, len(currentBatch))
		for j, id := range currentBatch {
			item := batch.item(id)
			parentDBID, ok := resolved[item.parentID]
			if !ok {
				return errors.New("property parent is not resolved")
			}
			valueID := dictIDs[item.entity.value]
			batchIndex[rowKey{entityType: item.entity.entityType, valueID: valueID, parentID: parentDBID}] = id
			placeholders[j] = "(?, ?, ?, ?, ?, ?, ?, ?)"
			values = append(values, item.entity.entityType, valueID, states[id].outOfScope, item.entity.category, states[id].depthStrict, states[id].depthRelaxed, parentDBID, nil)
		}

		query := fmt.Sprintf(`INSERT INTO entities(type, value_id, out_of_scope, category, depth_strict, depth_relaxed, parent_id, anchor_id) VALUES %s
		                      ON CONFLICT(type, value_id, parent_id) WHERE category = 'property' DO UPDATE SET
		                        out_of_scope = out_of_scope OR excluded.out_of_scope,
		                        category = excluded.category,
		                        depth_strict = MIN(depth_strict, excluded.depth_strict),
		                        depth_relaxed = MIN(depth_relaxed, excluded.depth_relaxed)
		                      RETURNING id, type, value_id, parent_id, out_of_scope, depth_strict, depth_relaxed`, strings.Join(placeholders, ","))
		rows, err := tx.QueryContext(ctx, query, values...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var dbID int64
			var entityType string
			var valueID int64
			var parentID int64
			var outOfScope bool
			var depthStrict int
			var depthRelaxed int
			if err := rows.Scan(&dbID, &entityType, &valueID, &parentID, &outOfScope, &depthStrict, &depthRelaxed); err != nil {
				if closeErr := rows.Close(); closeErr != nil {
					return err
				}
				return err
			}
			tempID := batchIndex[rowKey{entityType: entityType, valueID: valueID, parentID: parentID}]
			resolved[tempID] = dbID
			states[tempID].dbID = dbID
			states[tempID].outOfScope = outOfScope
			states[tempID].depthStrict = depthStrict
			states[tempID].depthRelaxed = depthRelaxed
		}
		if err := rows.Err(); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return err
			}
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}

	return nil
}

func insertDictionaryValues(ctx context.Context, tx *sql.Tx, values map[string]struct{}) error {
	if len(values) == 0 {
		return nil
	}

	items := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			items = append(items, value)
		}
	}
	if len(items) == 0 {
		return nil
	}

	const batchSize = sqliteMaxParams // SQLite parameter limit is 999, one placeholder per dictionary row
	for i := 0; i < len(items); i += batchSize {
		end := i + batchSize
		if end > len(items) {
			end = len(items)
		}

		currentBatch := items[i:end]
		placeholders := make([]string, len(currentBatch))
		args := make([]interface{}, len(currentBatch))
		for j, value := range currentBatch {
			placeholders[j] = "(?)"
			args[j] = value
		}

		query := fmt.Sprintf(`INSERT OR IGNORE INTO dictionary(value) VALUES %s`, strings.Join(placeholders, ","))
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return err
		}
	}

	return nil
}

func loadExistingEntities(ctx context.Context, tx *sql.Tx, entities map[string]entityFields) (map[string]*entityAgg, error) {
	aggMap := make(map[string]*entityAgg, len(entities))
	if len(entities) == 0 {
		return aggMap, nil
	}

	keys := make([]string, 0, len(entities))
	for key := range entities {
		keys = append(keys, key)
	}

	const batchSize = sqliteMaxParams / 2 // 2 fields per lookup pair, 450 * 2 < 999 SQLite parameter limit
	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}

		currentBatch := keys[i:end]
		placeholders := make([]string, len(currentBatch))
		args := make([]interface{}, 0, len(currentBatch)*2)
		for j, key := range currentBatch {
			entity := entities[key]
			placeholders[j] = "(e.type = ? AND d.value = ?)"
			args = append(args, entity.entityType, entity.value)
		}

		query := `SELECT e.type, d.value, e.out_of_scope, e.depth_strict, COALESCE(a.depth_relaxed, e.depth_relaxed), e.category, e.is_anchor
		          FROM entities e
		          JOIN dictionary d ON e.value_id = d.id
		          LEFT JOIN entities a ON e.anchor_id = a.id
		          WHERE ` + strings.Join(placeholders, " OR ")
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var entityType string
			var value string
			var outOfScope bool
			var depthStrict int
			var depthRelaxed int
			var category string
			var isAnchor bool
			if err := rows.Scan(&entityType, &value, &outOfScope, &depthStrict, &depthRelaxed, &category, &isAnchor); err != nil {
				if closeErr := rows.Close(); closeErr != nil {
					return nil, err
				}
				return nil, err
			}

			aggMap[entityKey(entityType, value)] = &entityAgg{
				entity: schema.Entity{
					Type:     entityType,
					Value:    value,
					Category: normalizeCategory(category),
				},
				outOfScope:   outOfScope,
				depthStrict:  depthStrict,
				depthRelaxed: depthRelaxed,
				isAnchor:     isAnchor,
			}
		}

		if err := rows.Err(); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return nil, err
			}
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}

	return aggMap, nil
}

// Store saves incoming data to the project database and returns an updated entity list.
func Store(ctx context.Context, data *schema.ProcessorToRepoData) (resData *schema.RepoToDispatcherData, err error) {
	if data == nil {
		return nil, errors.New("data is nil")
	}
	if data.SourceEntityID == 0 {
		return nil, errors.New("source entity id is empty")
	}
	if data.SourceEntity.Type == "" || data.SourceEntity.Value == "" {
		return nil, errors.New("source entity is empty")
	}

	internalName, err := ResolveWorkspaceRoute(data.ProjectID)
	if err != nil {
		return nil, err
	}

	dbPath := filepath.Join(StorageProjectsDir, internalName+".db")
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

	source, err := loadStoredEntity(ctx, tx, data.SourceEntityID)
	if err != nil {
		return nil, err
	}

	batchModel, err := buildStoreBatch(data, source.entity)
	if err != nil {
		return nil, err
	}

	states := make([]entityState, len(batchModel.entities)+1)
	for i := 1; i < len(states); i++ {
		states[i].depthStrict = unresolvedDepth
		states[i].depthRelaxed = unresolvedDepth
	}
	for _, id := range batchModel.nodeIDs {
		states[id].isAnchor = true
	}
	states[batchModel.rootID] = entityState{
		dbID:         source.id,
		outOfScope:   source.outOfScope,
		depthStrict:  source.depthStrict,
		depthRelaxed: source.depthRelaxed,
		anchor:       source.anchor,
		isAnchor:     source.isAnchor,
	}

	if err := loadNodeStates(ctx, tx, &batchModel, states); err != nil {
		return nil, err
	}

	resolvedIDs := make(map[batchEntityID]int64, len(batchModel.entities))
	resolvedIDs[batchModel.rootID] = data.SourceEntityID

	states[batchModel.rootID].isAnchor = false
	for _, item := range batchModel.results {
		states[item.sourceID].isAnchor = false
		targetState := &states[item.targetID]
		targetState.isAnchor = false
		targetState.outOfScope = targetState.outOfScope || batchModel.item(item.targetID).outOfScope || item.result.OutOfScope
	}

	for i := 0; i < len(batchModel.entities); i++ {
		changed := false
		for _, item := range batchModel.results {
			sourceState := &states[item.sourceID]
			if sourceState.depthStrict == unresolvedDepth {
				continue
			}

			targetState := &states[item.targetID]
			targetEntity := batchModel.item(item.targetID).entity
			if targetEntity.category == "property" {
				if sourceState.depthStrict < targetState.depthStrict {
					targetState.depthStrict = sourceState.depthStrict
					changed = true
				}
				if sourceState.depthRelaxed < targetState.depthRelaxed {
					targetState.depthRelaxed = sourceState.depthRelaxed
					changed = true
				}
				continue
			}

			newDepthStrict := sourceState.depthStrict + 1
			if newDepthStrict < targetState.depthStrict {
				targetState.depthStrict = newDepthStrict
				changed = true
			}

			if item.result.Anchor != "" {
				anchorID, ok := batchModel.nodeIndex[nodeKey{entityType: AnchorEntityType, value: item.result.Anchor}]
				if ok {
					anchorState := &states[anchorID]
					newAnchorDepth := sourceState.depthRelaxed + 1
					if newAnchorDepth < anchorState.depthRelaxed {
						anchorState.depthRelaxed = newAnchorDepth
						changed = true
					}
					if anchorState.depthRelaxed < targetState.depthRelaxed {
						targetState.depthRelaxed = anchorState.depthRelaxed
						targetState.anchor = item.result.Anchor
						changed = true
					}
				}
			} else {
				newDepthRelaxed := sourceState.depthRelaxed + 1
				if newDepthRelaxed < targetState.depthRelaxed {
					targetState.depthRelaxed = newDepthRelaxed
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	dictIDs, err := upsertDictionaryIDs(ctx, tx, collectBatchValues(&batchModel))
	if err != nil {
		return nil, err
	}

	anchorIDs := make([]batchEntityID, 0, len(batchModel.nodeIDs))
	nodeIDs := make([]batchEntityID, 0, len(batchModel.nodeIDs))
	for _, id := range batchModel.nodeIDs {
		if states[id].isAnchor {
			anchorIDs = append(anchorIDs, id)
			continue
		}
		nodeIDs = append(nodeIDs, id)
	}

	if err := upsertAnchorNodes(ctx, tx, &batchModel, anchorIDs, states, dictIDs, resolvedIDs); err != nil {
		return nil, err
	}
	if err := upsertRegularNodes(ctx, tx, &batchModel, nodeIDs, states, dictIDs, resolvedIDs); err != nil {
		return nil, err
	}
	if err := syncNodeAnchors(ctx, tx, &batchModel, nodeIDs, states, resolvedIDs); err != nil {
		return nil, err
	}

	pendingProperties := batchModel.pendingProperties()
	for len(pendingProperties) > 0 {
		layer := nextResolvedPropertyLayer(&batchModel, pendingProperties, resolvedIDs)
		if len(layer) == 0 {
			return nil, errors.New("property layer could not be resolved")
		}
		if err := upsertPropertyLayer(ctx, tx, &batchModel, layer, states, dictIDs, resolvedIDs); err != nil {
			return nil, err
		}
	}

	rawDataIDs := make(map[string]sql.NullInt64, len(data.FunctionRawData))
	for functionName, rawData := range data.FunctionRawData {
		if rawData == "" {
			rawDataIDs[functionName] = sql.NullInt64{Valid: false}
			continue
		}

		res, err := tx.ExecContext(ctx, "INSERT INTO raw_data (raw_data) VALUES (?)", rawData)
		if err != nil {
			return nil, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return nil, err
		}
		rawDataIDs[functionName] = sql.NullInt64{Int64: id, Valid: true}
	}

	type resultCtx struct {
		tempSourceID batchEntityID
		tempTargetID batchEntityID
		srcID        int64
		tgtID        int64
		result       schema.ProcessorToRepoValidResult
	}

	resultItems := make([]resultCtx, 0, len(batchModel.results))
	relationItems := make([]resultCtx, 0, len(batchModel.results))
	for _, item := range batchModel.results {
		srcID := resolvedIDs[item.sourceID]
		if srcID == 0 && item.sourceID == batchModel.rootID {
			srcID = data.SourceEntityID
		}
		tgtID := resolvedIDs[item.targetID]
		if tgtID == 0 {
			continue
		}

		resolvedItem := resultCtx{
			tempSourceID: item.sourceID,
			tempTargetID: item.targetID,
			srcID:        srcID,
			tgtID:        tgtID,
			result:       item.result,
		}
		resultItems = append(resultItems, resolvedItem)
		if srcID != 0 && srcID != tgtID {
			relationItems = append(relationItems, resolvedItem)
		}
	}

	type tagItem struct {
		eid int64
		tag string
	}

	tagItems := make([]tagItem, 0)
	for _, item := range resultItems {
		for _, tag := range item.result.Tags {
			if tag != "" {
				tagItems = append(tagItems, tagItem{eid: item.tgtID, tag: tag})
			}
		}
	}
	if len(tagItems) > 0 {
		const batchSize = sqliteMaxParams / 2 // 2 fields per row, 499 * 2 < 999 SQLite parameter limit
		for i := 0; i < len(tagItems); i += batchSize {
			end := i + batchSize
			if end > len(tagItems) {
				end = len(tagItems)
			}

			currentBatch := tagItems[i:end]
			placeholders := make([]string, 0, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*2)
			for _, item := range currentBatch {
				placeholders = append(placeholders, "(?, ?)")
				values = append(values, item.eid, item.tag)
			}

			query := fmt.Sprintf("INSERT OR IGNORE INTO entity_tags(entity_id, tag) VALUES %s", strings.Join(placeholders, ","))
			if _, err := tx.ExecContext(ctx, query, values...); err != nil {
				return nil, err
			}
		}
	}

	type relKey struct {
		srcID int64
		tgtID int64
	}

	uniqueRelations := make([]relKey, 0, len(relationItems))
	seenRelations := make(map[relKey]struct{}, len(relationItems))
	for _, item := range relationItems {
		key := relKey{srcID: item.srcID, tgtID: item.tgtID}
		if _, ok := seenRelations[key]; ok {
			continue
		}
		seenRelations[key] = struct{}{}
		uniqueRelations = append(uniqueRelations, key)
	}

	if len(uniqueRelations) > 0 {
		const batchSize = sqliteMaxParams / 2 // 2 fields per row, 499 * 2 < 999 SQLite parameter limit
		for i := 0; i < len(uniqueRelations); i += batchSize {
			end := i + batchSize
			if end > len(uniqueRelations) {
				end = len(uniqueRelations)
			}

			currentBatch := uniqueRelations[i:end]
			placeholders := make([]string, 0, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*2)
			for _, item := range currentBatch {
				placeholders = append(placeholders, "(?, ?)")
				values = append(values, item.srcID, item.tgtID)
			}

			query := fmt.Sprintf("INSERT OR IGNORE INTO relations(source_entity_id, target_entity_id) VALUES %s", strings.Join(placeholders, ","))
			if _, err := tx.ExecContext(ctx, query, values...); err != nil {
				return nil, err
			}
		}
	}

	relationIDMap := make(map[relKey]int64, len(uniqueRelations))
	if len(uniqueRelations) > 0 {
		const batchSize = sqliteMaxParams / 2 // 2 fields per lookup pair, 499 * 2 < 999 SQLite parameter limit
		for i := 0; i < len(uniqueRelations); i += batchSize {
			end := i + batchSize
			if end > len(uniqueRelations) {
				end = len(uniqueRelations)
			}

			currentBatch := uniqueRelations[i:end]
			placeholders := make([]string, 0, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*2)
			for _, item := range currentBatch {
				placeholders = append(placeholders, "(source_entity_id = ? AND target_entity_id = ?)")
				values = append(values, item.srcID, item.tgtID)
			}

			query := fmt.Sprintf("SELECT id, source_entity_id, target_entity_id FROM relations WHERE %s", strings.Join(placeholders, " OR "))
			rows, err := tx.QueryContext(ctx, query, values...)
			if err != nil {
				return nil, err
			}

			for rows.Next() {
				var relationID int64
				var srcID int64
				var tgtID int64
				if err := rows.Scan(&relationID, &srcID, &tgtID); err != nil {
					if closeErr := rows.Close(); closeErr != nil {
						return nil, err
					}
					return nil, err
				}
				relationIDMap[relKey{srcID: srcID, tgtID: tgtID}] = relationID
			}

			if err := rows.Err(); err != nil {
				if closeErr := rows.Close(); closeErr != nil {
					return nil, err
				}
				return nil, err
			}
			if err := rows.Close(); err != nil {
				return nil, err
			}
		}
	}

	if len(relationItems) > 0 {
		const batchSize = sqliteMaxParams / 4 // 4 fields per row, 249 * 4 < 999 SQLite parameter limit
		for i := 0; i < len(relationItems); i += batchSize {
			end := i + batchSize
			if end > len(relationItems) {
				end = len(relationItems)
			}

			currentBatch := relationItems[i:end]
			placeholders := make([]string, 0, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*4)
			for _, item := range currentBatch {
				relationID := relationIDMap[relKey{srcID: item.srcID, tgtID: item.tgtID}]
				placeholders = append(placeholders, "(?, ?, ?, ?)")
				values = append(values, relationID, data.ModuleName, item.result.Function, item.result.Context)
			}

			query := fmt.Sprintf("INSERT INTO observations(relation_id, module_name, function_name, context) VALUES %s", strings.Join(placeholders, ","))
			if _, err := tx.ExecContext(ctx, query, values...); err != nil {
				return nil, err
			}
		}
	}

	if len(data.Errors) > 0 {
		const batchSize = sqliteMaxParams / 5 // 5 fields per row, 199 * 5 < 999 SQLite parameter limit
		for i := 0; i < len(data.Errors); i += batchSize {
			end := i + batchSize
			if end > len(data.Errors) {
				end = len(data.Errors)
			}

			currentBatch := data.Errors[i:end]
			placeholders := make([]string, 0, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*5)
			for _, item := range currentBatch {
				placeholders = append(placeholders, "(?, ?, ?, ?, ?)")
				values = append(values, data.SourceEntityID, data.ModuleName, item.Function, item.ErrorType, item.ErrorText)
			}

			query := fmt.Sprintf("INSERT INTO errors(source_entity_id, module_name, function_name, error_type, error_text) VALUES %s", strings.Join(placeholders, ","))
			if _, err := tx.ExecContext(ctx, query, values...); err != nil {
				return nil, err
			}
		}
	}

	type logItem struct {
		eid       int64
		fn        string
		ok        int
		idRawData sql.NullInt64
	}

	logMap := make(map[string]logItem)
	addLog := func(entityID int64, functionName string, ok int, rawDataID sql.NullInt64) {
		if entityID == 0 || functionName == "" {
			return
		}

		key := fmt.Sprintf("%d:%s", entityID, functionName)
		existing, exists := logMap[key]
		if !exists || (!existing.idRawData.Valid && rawDataID.Valid) {
			logMap[key] = logItem{eid: entityID, fn: functionName, ok: ok, idRawData: rawDataID}
		}
	}

	for _, item := range resultItems {
		rawDataID := rawDataIDs[item.result.Function]
		addLog(data.SourceEntityID, item.result.Function, 1, rawDataID)
		addLog(item.srcID, item.result.Function, 1, rawDataID)
		if item.result.Applied {
			addLog(item.tgtID, item.result.Function, 1, rawDataID)
		}
	}
	for _, item := range data.Errors {
		addLog(data.SourceEntityID, item.Function, 0, rawDataIDs[item.Function])
	}
	for _, functionName := range data.FunctionsWithoutResults {
		addLog(data.SourceEntityID, functionName, 1, rawDataIDs[functionName])
	}

	if len(logMap) > 0 {
		logs := make([]logItem, 0, len(logMap))
		for _, item := range logMap {
			logs = append(logs, item)
		}

		const batchSize = sqliteMaxParams / 5 // 5 fields per row, 199 * 5 < 999 SQLite parameter limit
		for i := 0; i < len(logs); i += batchSize {
			end := i + batchSize
			if end > len(logs) {
				end = len(logs)
			}

			currentBatch := logs[i:end]
			placeholders := make([]string, 0, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*5)
			for _, item := range currentBatch {
				placeholders = append(placeholders, "(?, ?, ?, ?, ?)")
				values = append(values, item.eid, data.ModuleName, item.fn, item.ok, item.idRawData)
			}

			query := fmt.Sprintf(`INSERT INTO entity_function_log(entity_id, module_name, function_name, is_success, id_raw_data)
			                      VALUES %s ON CONFLICT(entity_id, module_name, function_name)
			                      DO UPDATE SET is_success = excluded.is_success, id_raw_data = excluded.id_raw_data`, strings.Join(placeholders, ","))
			if _, err := tx.ExecContext(ctx, query, values...); err != nil {
				return nil, err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	targets := make([]entityWithID, 0, len(resultItems))
	for _, item := range batchModel.results {
		targetID := resolvedIDs[item.targetID]
		if targetID == 0 {
			continue
		}
		targetEntity := batchModel.item(item.targetID).entity
		targetState := states[item.targetID]
		targets = append(targets, entityWithID{
			id: targetID,
			e: schema.Entity{
				Type:     targetEntity.entityType,
				Value:    targetEntity.value,
				Category: targetEntity.category,
			},
			outOfScope:   targetState.outOfScope,
			depthStrict:  targetState.depthStrict,
			depthRelaxed: targetState.depthRelaxed,
		})
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

func upsertAndGetEntities(ctx context.Context, tx *sql.Tx, aggMap map[string]*entityAgg) (map[string]entityMeta, error) {
	if len(aggMap) == 0 {
		return map[string]entityMeta{}, nil
	}

	entityList := make([]*entityAgg, 0, len(aggMap))
	uniqueValues := make(map[string]struct{})
	for _, agg := range aggMap {
		agg.entity.Category = normalizeCategory(agg.entity.Category)
		entityList = append(entityList, agg)
		if agg.entity.Value != "" {
			uniqueValues[agg.entity.Value] = struct{}{}
		}
		if agg.anchor != "" {
			uniqueValues[agg.anchor] = struct{}{}
		}
	}

	if err := insertDictionaryValues(ctx, tx, uniqueValues); err != nil {
		return nil, err
	}

	anchorDepths := make(map[string]int)
	for _, agg := range entityList {
		if agg.anchor == "" {
			continue
		}
		depth, exists := anchorDepths[agg.anchor]
		if !exists || agg.depthRelaxed < depth {
			anchorDepths[agg.anchor] = agg.depthRelaxed
		}
	}

	if len(anchorDepths) > 0 {
		type anchorItem struct {
			domain  string
			relaxed int
		}

		anchors := make([]anchorItem, 0, len(anchorDepths))
		for domain, relaxed := range anchorDepths {
			anchors = append(anchors, anchorItem{domain: domain, relaxed: relaxed})
		}

		const batchSize = sqliteMaxParams / 3 // 3 fields per row, 333 * 3 < 999 SQLite parameter limit
		for i := 0; i < len(anchors); i += batchSize {
			end := i + batchSize
			if end > len(anchors) {
				end = len(anchors)
			}

			currentBatch := anchors[i:end]
			placeholders := make([]string, len(currentBatch))
			values := make([]interface{}, 0, len(currentBatch)*3)
			for j, item := range currentBatch {
				placeholders[j] = "(?, (SELECT id FROM dictionary WHERE value=?), 1, 999999, ?)"
				values = append(values, AnchorEntityType, item.domain, item.relaxed)
			}

			query := fmt.Sprintf(`INSERT INTO entities(type, value_id, is_anchor, depth_strict, depth_relaxed) VALUES %s
			                      ON CONFLICT(type, value_id) DO UPDATE SET depth_relaxed = MIN(depth_relaxed, excluded.depth_relaxed)`, strings.Join(placeholders, ","))
			if _, err := tx.ExecContext(ctx, query, values...); err != nil {
				return nil, err
			}
		}
	}

	const batchSize = sqliteMaxParams / 9 // 9 fields per row, 111 * 9 < 999 SQLite parameter limit
	for i := 0; i < len(entityList); i += batchSize {
		end := i + batchSize
		if end > len(entityList) {
			end = len(entityList)
		}

		currentBatch := entityList[i:end]
		placeholders := make([]string, len(currentBatch))
		values := make([]interface{}, 0, len(currentBatch)*9)
		for j, agg := range currentBatch {
			isAnchor := 0
			if agg.isAnchor {
				isAnchor = 1
			}
			placeholders[j] = "(?, (SELECT id FROM dictionary WHERE value=?), ?, ?, ?, ?, ?, (SELECT id FROM entities WHERE type=? AND value_id=(SELECT id FROM dictionary WHERE value=?)))"
			values = append(values, agg.entity.Type, agg.entity.Value, agg.outOfScope, agg.entity.Category, isAnchor, agg.depthStrict, agg.depthRelaxed, AnchorEntityType, agg.anchor)
		}

		query := fmt.Sprintf(`INSERT INTO entities(type, value_id, out_of_scope, category, is_anchor, depth_strict, depth_relaxed, anchor_id) VALUES %s
		                      ON CONFLICT(type, value_id) DO UPDATE SET
		                        out_of_scope = out_of_scope OR excluded.out_of_scope,
		                        category = excluded.category,
		                        is_anchor = MIN(is_anchor, excluded.is_anchor),
		                        depth_strict = MIN(depth_strict, excluded.depth_strict),
		                        depth_relaxed = MIN(depth_relaxed, excluded.depth_relaxed),
		                        anchor_id = COALESCE(excluded.anchor_id, anchor_id)`, strings.Join(placeholders, ","))
		if _, err := tx.ExecContext(ctx, query, values...); err != nil {
			return nil, err
		}
	}

	entityMetaMap := make(map[string]entityMeta, len(entityList))
	for i := 0; i < len(entityList); i += batchSize {
		end := i + batchSize
		if end > len(entityList) {
			end = len(entityList)
		}

		currentBatch := entityList[i:end]
		placeholders := make([]string, len(currentBatch))
		values := make([]interface{}, 0, len(currentBatch)*2)
		for j, agg := range currentBatch {
			placeholders[j] = "(e.type = ? AND d.value = ?)"
			values = append(values, agg.entity.Type, agg.entity.Value)
		}

		query := `SELECT e.id, e.type, d.value, e.out_of_scope, e.depth_strict, COALESCE(a.depth_relaxed, e.depth_relaxed)
		          FROM entities e
		          JOIN dictionary d ON e.value_id = d.id
		          LEFT JOIN entities a ON e.anchor_id = a.id
		          WHERE ` + strings.Join(placeholders, " OR ")
		rows, err := tx.QueryContext(ctx, query, values...)
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var id int64
			var entityType string
			var value string
			var outOfScope bool
			var depthStrict int
			var depthRelaxed int
			if err := rows.Scan(&id, &entityType, &value, &outOfScope, &depthStrict, &depthRelaxed); err != nil {
				if closeErr := rows.Close(); closeErr != nil {
					return nil, err
				}
				return nil, err
			}

			entityMetaMap[entityKey(entityType, value)] = entityMeta{
				id:           id,
				outOfScope:   outOfScope,
				depthStrict:  depthStrict,
				depthRelaxed: depthRelaxed,
			}
		}

		if err := rows.Err(); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
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
func GetProjectStatus(ctx context.Context, projectID string) (pending []schema.PendingTask, errors []schema.PendingTask, err error) {
	internalName, err := ResolveWorkspaceRoute(projectID)
	if err != nil {
		return nil, nil, err
	}

	dbPath := filepath.Join(StorageProjectsDir, internalName+".db")
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

	masterDBPath := filepath.Join(StorageBaseDir, MasterDBName)
	// modernc/sqlite doesn't always support parameterized ATTACH, safe to format since path is controlled
	if _, err := db.ExecContext(ctx, fmt.Sprintf("ATTACH DATABASE '%s' AS master", masterDBPath)); err != nil {
		return nil, nil, err
	}

	pendingQuery := `
		SELECT DISTINCT m.module_name, m.function, e.type,
		       (SELECT GROUP_CONCAT(tag) FROM entity_tags WHERE entity_id = e.id) as tags,
		       e.depth_strict, COALESCE(a.depth_relaxed, e.depth_relaxed)
		FROM entities e
		LEFT JOIN entities a ON e.anchor_id = a.id
		JOIN master.modules m ON e.type = m.input_type
		LEFT JOIN entity_function_log efl
		  ON e.id = efl.entity_id AND m.module_name = efl.module_name AND m.function = efl.function_name
		WHERE efl.entity_id IS NULL AND m.function != '' AND e.out_of_scope = FALSE AND e.is_anchor = 0 AND m.is_enabled = 1
			ORDER BY e.id, m.module_name, m.function`

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
		var dStrict, dRelaxed int
		if err := rows.Scan(&mod, &fn, &eType, &tagsStr, &dStrict, &dRelaxed); err == nil {
			var eTags []string
			if tagsStr.Valid && tagsStr.String != "" {
				eTags = strings.Split(tagsStr.String, ",")
			}
			pending = append(pending, schema.PendingTask{
				ModuleName:   mod,
				Function:     fn,
				EntityType:   eType,
				EntityTags:   eTags,
				DepthStrict:  dStrict,
				DepthRelaxed: dRelaxed,
			})
		}
	}
	errorQuery := `
		SELECT DISTINCT efl.module_name, efl.function_name, e.type,
		       (SELECT GROUP_CONCAT(tag) FROM entity_tags WHERE entity_id = e.id) as tags,
		       e.depth_strict, COALESCE(a.depth_relaxed, e.depth_relaxed)
		FROM entity_function_log efl
		JOIN entities e ON e.id = efl.entity_id
		LEFT JOIN entities a ON e.anchor_id = a.id
		JOIN master.modules m ON efl.module_name = m.module_name AND efl.function_name = m.function
		WHERE efl.is_success = 0 AND e.out_of_scope = FALSE AND m.is_enabled = 1
		ORDER BY e.id, efl.module_name, efl.function_name`
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
		var mod, fn, eType string
		var tagsStr sql.NullString
		var dStrict, dRelaxed int
		if err := rowsErr.Scan(&mod, &fn, &eType, &tagsStr, &dStrict, &dRelaxed); err == nil {
			var eTags []string
			if tagsStr.Valid && tagsStr.String != "" {
				eTags = strings.Split(tagsStr.String, ",")
			}
			errors = append(errors, schema.PendingTask{
				ModuleName:   mod,
				Function:     fn,
				EntityType:   eType,
				EntityTags:   eTags,
				DepthStrict:  dStrict,
				DepthRelaxed: dRelaxed,
			})
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

	dbPath := filepath.Join(StorageProjectsDir, internalName+".db")
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

	masterDBPath := filepath.Join(StorageBaseDir, MasterDBName)
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

	dbPath := filepath.Join(StorageProjectsDir, internalName+".db")
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

	masterDBPath := filepath.Join(StorageBaseDir, MasterDBName)
	if _, err := db.ExecContext(ctx, fmt.Sprintf("ATTACH DATABASE '%s' AS master", masterDBPath)); err != nil {
		return nil, err
	}

	var queryParts []string
	if resumePending {
		queryParts = append(queryParts, `
			SELECT DISTINCT e.id, e.type, d.value, e.out_of_scope, e.depth_strict, COALESCE(a.depth_relaxed, e.depth_relaxed)
			FROM entities e
			JOIN dictionary d ON e.value_id = d.id
			LEFT JOIN entities a ON e.anchor_id = a.id
			JOIN master.modules m ON e.type = m.input_type
			LEFT JOIN entity_function_log efl
			  ON e.id = efl.entity_id AND m.module_name = efl.module_name AND m.function = efl.function_name
			WHERE efl.entity_id IS NULL AND m.function != '' AND e.out_of_scope = FALSE AND e.is_anchor = 0 AND m.is_enabled = 1`)
	}
	if retryErrors {
		queryParts = append(queryParts, `
			SELECT DISTINCT e.id, e.type, d.value, e.out_of_scope, e.depth_strict, COALESCE(a.depth_relaxed, e.depth_relaxed)
			FROM entities e
			JOIN dictionary d ON e.value_id = d.id
			LEFT JOIN entities a ON e.anchor_id = a.id
			JOIN entity_function_log efl ON e.id = efl.entity_id
			JOIN master.modules m ON efl.module_name = m.module_name AND efl.function_name = m.function
			WHERE efl.is_success = 0 AND e.out_of_scope = FALSE AND m.is_enabled = 1`)
	}

	if len(queryParts) == 0 {
		return nil, nil
	}

	resumeQuery := "SELECT * FROM (" + strings.Join(queryParts, " UNION ") + ") ORDER BY id"
	rows, rErr := db.QueryContext(ctx, resumeQuery)
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
		var ds, dr int
		if sErr := rows.Scan(&id, &t, &v, &oos, &ds, &dr); sErr != nil {
			return nil, sErr
		}
		entities = append(entities, entityWithID{
			id:           id,
			e:            schema.Entity{Type: t, Value: v},
			outOfScope:   oos,
			depthStrict:  ds,
			depthRelaxed: dr,
		})
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
	id           int64
	e            schema.Entity
	outOfScope   bool
	depthStrict  int
	depthRelaxed int
}

func buildBatchItems(ctx context.Context, db *sql.DB, entities []entityWithID) ([]schema.RepoToDispatcherBatchItem, error) {
	if len(entities) == 0 {
		return nil, nil
	}

	entityFunctions := make(map[int64][]schema.ModuleFunction)
	entityTags := make(map[int64][]string)
	lookupIDs := make([]int64, 0, len(entities))
	seenIDs := make(map[int64]struct{}, len(entities))
	for _, entity := range entities {
		if _, ok := seenIDs[entity.id]; ok {
			continue
		}
		seenIDs[entity.id] = struct{}{}
		lookupIDs = append(lookupIDs, entity.id)
	}

	const batchSize = sqliteMaxParams // 1 field per entity in IN() clauses, capped at SQLite parameter limit

	for i := 0; i < len(lookupIDs); i += batchSize {
		end := i + batchSize
		if end > len(lookupIDs) {
			end = len(lookupIDs)
		}

		currentBatch := lookupIDs[i:end]
		placeholders := make([]string, len(currentBatch))
		args := make([]interface{}, len(currentBatch))
		for j, entityID := range currentBatch {
			placeholders[j] = "?"
			args[j] = entityID
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
			SourceEntityID:     ent.id,
			Entity:             e,
			OutOfScope:         ent.outOfScope,
			DepthStrict:        ent.depthStrict,
			DepthRelaxed:       ent.depthRelaxed,
			CompletedFunctions: entityFunctions[ent.id],
		})
	}
	return batch, nil
}

// GetProjectStats retrieves the counts of unique entity values grouped by category and type.
func GetProjectStats(ctx context.Context, projectID string) (map[string]map[string]int, error) {
	internalName, err := ResolveWorkspaceRoute(projectID)
	if err != nil {
		return nil, err
	}

	dbPath := filepath.Join(StorageProjectsDir, internalName+".db")
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

	query := "SELECT e.category, e.type, COUNT(DISTINCT d.value) FROM entities e JOIN dictionary d ON e.value_id = d.id WHERE e.is_anchor = 0 GROUP BY e.category, e.type"
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

	stats := make(map[string]map[string]int)
	for rows.Next() {
		var cat, t string
		var c int
		if err := rows.Scan(&cat, &t, &c); err == nil {
			if stats[cat] == nil {
				stats[cat] = make(map[string]int)
			}
			stats[cat][t] = c
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

	masterDBPath := filepath.Join(StorageBaseDir, MasterDBName)
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

	dbPath := filepath.Join(StorageProjectsDir, internalName+".db")
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
			e1.id, e1.type, d1.value, e1.category, e1.out_of_scope, e1.depth_strict, COALESCE(a1.depth_relaxed, e1.depth_relaxed),
			e2.id, e2.type, d2.value, e2.category, e2.out_of_scope, e2.depth_strict, COALESCE(a2.depth_relaxed, e2.depth_relaxed),
			o.module_name, o.function_name, o.context, o.created_at
		FROM relations r
		JOIN entities e1 ON r.source_entity_id = e1.id
		JOIN dictionary d1 ON e1.value_id = d1.id
		LEFT JOIN entities a1 ON e1.anchor_id = a1.id
		JOIN entities e2 ON r.target_entity_id = e2.id
		JOIN dictionary d2 ON e2.value_id = d2.id
		LEFT JOIN entities a2 ON e2.anchor_id = a2.id
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
		edge     schema.EdgeData
		sourceID int64
	}
	var tempEdges []edgeWithID

	type rawDataKey struct {
		entityID   int64
		moduleName string
		funcName   string
	}
	neededRawData := make(map[rawDataKey]bool)
	nodes := make(map[string]schema.NodeData)

	idMap := make(map[int64]string)
	nodeCounter := 1

	getNodeID := func(dbID int64) string {
		if id, exists := idMap[dbID]; exists {
			return id
		}
		newID := "n" + strconv.Itoa(nodeCounter)
		nodeCounter++
		idMap[dbID] = newID
		return newID
	}

	for rows.Next() {
		var srcIDDb, tgtIDDb int64
		var srcType, srcValue, srcCategory string
		var tgtType, tgtValue, tgtCategory string
		var srcOutOfScope, tgtOutOfScope bool
		var srcDepthStrict, srcDepthRelaxed int
		var tgtDepthStrict, tgtDepthRelaxed int
		var moduleName, functionName, contextStr, createdAt string

		err := rows.Scan(
			&srcIDDb, &srcType, &srcValue, &srcCategory, &srcOutOfScope, &srcDepthStrict, &srcDepthRelaxed,
			&tgtIDDb, &tgtType, &tgtValue, &tgtCategory, &tgtOutOfScope, &tgtDepthStrict, &tgtDepthRelaxed,
			&moduleName, &functionName,
			&contextStr,
			&createdAt,
		)
		if err == nil {
			srcID := getNodeID(srcIDDb)
			tgtID := getNodeID(tgtIDDb)

			if _, exists := nodes[srcID]; !exists {
				nodes[srcID] = schema.NodeData{
					Type:         srcType,
					Value:        srcValue,
					Category:     srcCategory,
					OutOfScope:   srcOutOfScope,
					DepthStrict:  srcDepthStrict,
					DepthRelaxed: srcDepthRelaxed,
				}
			}

			if _, exists := nodes[tgtID]; !exists {
				nodes[tgtID] = schema.NodeData{
					Type:         tgtType,
					Value:        tgtValue,
					Category:     tgtCategory,
					OutOfScope:   tgtOutOfScope,
					DepthStrict:  tgtDepthStrict,
					DepthRelaxed: tgtDepthRelaxed,
				}
			}

			e := schema.EdgeData{
				SourceID:     srcID,
				TargetID:     tgtID,
				ModuleName:   moduleName,
				FunctionName: functionName,
				Context:      contextStr,
				CreatedAt:    createdAt,
			}
			tempEdges = append(tempEdges, edgeWithID{edge: e, sourceID: srcIDDb})
			if includeRawData {
				neededRawData[rawDataKey{srcIDDb, moduleName, functionName}] = true
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

	var edges []schema.EdgeData
	for _, te := range tempEdges {
		edges = append(edges, te.edge)
	}

	orphanQuery := `
		SELECT e.id, e.type, d.value, e.category, e.out_of_scope, e.depth_strict, COALESCE(a.depth_relaxed, e.depth_relaxed)
		FROM entities e
		JOIN dictionary d ON e.value_id = d.id
		LEFT JOIN entities a ON e.anchor_id = a.id
		WHERE e.is_anchor = 0
		ORDER BY e.id ASC
	`
	if orphanRows, oErr := db.QueryContext(ctx, orphanQuery); oErr == nil {
		for orphanRows.Next() {
			var dbID int64
			var eType, eValue, eCategory string
			var outOfScope bool
			var depthStrict, depthRelaxed int
			if err := orphanRows.Scan(&dbID, &eType, &eValue, &eCategory, &outOfScope, &depthStrict, &depthRelaxed); err == nil {
				if _, exists := idMap[dbID]; !exists {
					newID := getNodeID(dbID)
					nodes[newID] = schema.NodeData{
						Type:         eType,
						Value:        eValue,
						Category:     eCategory,
						OutOfScope:   outOfScope,
						DepthStrict:  depthStrict,
						DepthRelaxed: depthRelaxed,
					}
				}
			}
		}
		_ = orphanRows.Close()
	}

	tagsQuery := `SELECT entity_id, tag FROM entity_tags WHERE tag NOT LIKE '.%'`
	tagsRows, tErr := db.QueryContext(ctx, tagsQuery)
	if tErr == nil {
		for tagsRows.Next() {
			var dbID int64
			var tag string
			if err := tagsRows.Scan(&dbID, &tag); err == nil {
				if syntheticID, ok := idMap[dbID]; ok {
					if n, exists := nodes[syntheticID]; exists {
						n.Subtypes = append(n.Subtypes, tag)
						nodes[syntheticID] = n
					}
				}
			}
		}
		if err := tagsRows.Close(); err != nil {
			return nil, err
		}
	}

	return &schema.ProjectGraph{
		ProjectName:   projectName,
		InitialTarget: initialTarget,
		Nodes:         nodes,
		Edges:         edges,
	}, nil
}
