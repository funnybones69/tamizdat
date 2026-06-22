package rulesdb

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// Legacy flat schema (pre-folders). Used to verify backward-compat
// fallback when the DB has no routing_folders table / folder_id column.
const schemaSQL = `
CREATE TABLE routing_rules (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    priority             INTEGER NOT NULL,
    match_json           TEXT NOT NULL,
    outbound_tag         TEXT NOT NULL,
    description_override TEXT,
    enabled              INTEGER NOT NULL DEFAULT 1,
    created_at           INTEGER NOT NULL DEFAULT 0,
    updated_at           INTEGER NOT NULL DEFAULT 0
);
`

// Folders v1 schema (post-migration). Adds routing_folders table +
// folder_id column to routing_rules.
const schemaFoldersSQL = `
CREATE TABLE routing_folders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    priority    INTEGER NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE routing_rules (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    priority             INTEGER NOT NULL,
    match_json           TEXT NOT NULL,
    outbound_tag         TEXT NOT NULL,
    description_override TEXT,
    enabled              INTEGER NOT NULL DEFAULT 1,
    folder_id            INTEGER REFERENCES routing_folders(id),
    created_at           INTEGER NOT NULL DEFAULT 0,
    updated_at           INTEGER NOT NULL DEFAULT 0
);
`

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return db
}

func openTestDBWithFolders(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(schemaFoldersSQL); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return db
}

func TestLoadEmpty(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	rules, err := Load(db)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("want 0 rules, got %d", len(rules))
	}
}

func TestLoadAndOrder(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	rows := []struct {
		pr    int
		tag   string
		mjson string
	}{
		{2, "via-relay", `{"user":["alice"]}`},
		{1, "direct", `{"ip":["10.0.0.0/8"]}`},
		{3, "block", `{"port":"25"}`},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO routing_rules(priority,outbound_tag,match_json) VALUES(?,?,?)`,
			r.pr, r.tag, r.mjson); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	got, err := Load(db)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 rules, got %d", len(got))
	}
	if got[0].Priority != 1 || got[1].Priority != 2 || got[2].Priority != 3 {
		t.Fatalf("rules not in priority order: %+v", got)
	}
	if got[0].OutboundTag != "direct" || got[2].OutboundTag != "block" {
		t.Fatalf("tag mismatch: %+v", got)
	}
}

func TestLoadIgnoresDisabled(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO routing_rules(priority,outbound_tag,match_json,enabled) VALUES(1,'t','{}',0)`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := Load(db)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 (disabled), got %d", len(got))
	}
}

func TestBuildAndResolve(t *testing.T) {
	rules := []Loaded{
		{Priority: 1, OutboundTag: "via-relay", Match: Match{User: []string{"alice"}}},
		{Priority: 2, OutboundTag: "block", Match: Match{IP: []string{"10.0.0.0/8"}}},
	}
	disp, err := Build(rules, []string{"direct", "via-relay"}, "direct")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if disp == nil {
		t.Fatal("Build returned nil dispatcher")
	}
	snap := &Snapshot{Dispatcher: disp, DefaultTag: "direct"}

	// alice → via-relay rule
	if tag := ResolveTCP(context.Background(), snap, "1.2.3.4", 443, "tamizdat-in", "alice"); tag != "via-relay" {
		t.Errorf("alice: want via-relay, got %q", tag)
	}
	// 10.x → block
	if tag := ResolveTCP(context.Background(), snap, "10.5.5.5", 443, "tamizdat-in", "bob"); tag != "block" {
		t.Errorf("10.x: want block, got %q", tag)
	}
	// fallback → direct
	if tag := ResolveTCP(context.Background(), snap, "1.2.3.4", 443, "tamizdat-in", "bob"); tag != "direct" {
		t.Errorf("default: want direct, got %q", tag)
	}
	// nil snapshot → ""
	if tag := ResolveTCP(context.Background(), nil, "1.1.1.1", 80, "in", "x"); tag != "" {
		t.Errorf("nil snap: want \"\", got %q", tag)
	}
}

func TestBuildEmptyReturnsNil(t *testing.T) {
	disp, err := Build(nil, []string{"direct"}, "direct")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if disp != nil {
		t.Fatal("want nil dispatcher for empty rules")
	}
}

// ============================================================================
// Folders v1 (2026-05-10) — hierarchical loading tests.
// ============================================================================

// TestLoadHierarchical_FoldersInterleaveWithUngrouped verifies the
// "folders are first-class siblings of ungrouped rules in the global
// priority queue" semantics.
//
// Layout:
//
//	priority 1 :  ungrouped rule  →  R-ung-A
//	priority 2 :  Folder X        →  contains R-X1 (ip 1), R-X2 (ip 2)
//	priority 3 :  ungrouped rule  →  R-ung-B
//	priority 4 :  Folder Y        →  contains R-Y1 (ip 1)
//
// Expected slice order:
//
//	R-ung-A, R-X1, R-X2, R-ung-B, R-Y1
func TestLoadHierarchical_FoldersInterleaveWithUngrouped(t *testing.T) {
	db := openTestDBWithFolders(t)
	defer db.Close()
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	mustExec(`INSERT INTO routing_folders(id,name,priority,enabled) VALUES(1,'X',2,1),(2,'Y',4,1)`)
	mustExec(`INSERT INTO routing_rules(priority,outbound_tag,match_json,folder_id) VALUES
        (1,'ung-A','{"ip":["1.0.0.0/8"]}',NULL),
        (1,'X1','{"ip":["10.0.0.0/8"]}',1),
        (2,'X2','{"ip":["20.0.0.0/8"]}',1),
        (3,'ung-B','{"ip":["3.0.0.0/8"]}',NULL),
        (1,'Y1','{"ip":["100.0.0.0/8"]}',2)`)

	got, err := Load(db)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"ung-A", "X1", "X2", "ung-B", "Y1"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: want %d, got %d (%v)", len(want), len(got), tags(got))
	}
	for i, w := range want {
		if got[i].OutboundTag != w {
			t.Errorf("position %d: want %q, got %q (full: %v)", i, w, got[i].OutboundTag, tags(got))
		}
	}
}

// TestLoadHierarchical_FolderEnabledFalseHidesAllChildren verifies a
// disabled folder hides every rule it contains from Load output, even
// when each rule itself has enabled=1.
func TestLoadHierarchical_FolderEnabledFalseHidesAllChildren(t *testing.T) {
	db := openTestDBWithFolders(t)
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO routing_folders(id,name,priority,enabled) VALUES(1,'X',1,0)`); err != nil {
		t.Fatalf("insert folder: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO routing_rules(priority,outbound_tag,match_json,folder_id) VALUES
        (1,'X1','{}',1),
        (2,'X2','{}',1)`); err != nil {
		t.Fatalf("insert rules: %v", err)
	}
	got, err := Load(db)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 rules (folder disabled), got %d (%v)", len(got), tags(got))
	}
}

// TestLoadHierarchical_DisabledRuleInsideEnabledFolder verifies a
// disabled rule is hidden even if its parent folder is enabled.
func TestLoadHierarchical_DisabledRuleInsideEnabledFolder(t *testing.T) {
	db := openTestDBWithFolders(t)
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO routing_folders(id,name,priority,enabled) VALUES(1,'X',1,1)`); err != nil {
		t.Fatalf("insert folder: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO routing_rules(priority,outbound_tag,match_json,enabled,folder_id) VALUES
        (1,'X1','{}',1,1),
        (2,'X2','{}',0,1),
        (3,'X3','{}',1,1)`); err != nil {
		t.Fatalf("insert rules: %v", err)
	}
	got, err := Load(db)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"X1", "X3"}
	if len(got) != len(want) {
		t.Fatalf("want %d rules, got %d (%v)", len(want), len(got), tags(got))
	}
	for i, w := range want {
		if got[i].OutboundTag != w {
			t.Errorf("position %d: want %q, got %q", i, w, got[i].OutboundTag)
		}
	}
}

// TestLoadHierarchical_FolderReorder verifies that "moving the whole
// folder up" (which the panel implements as folder.priority swap)
// repositions every contained rule together in the global queue.
func TestLoadHierarchical_FolderReorder(t *testing.T) {
	db := openTestDBWithFolders(t)
	defer db.Close()
	// Initial: Folder X (gp=1) has R-X1; ungrouped R-ung at gp=2;
	// Folder Y (gp=3) has R-Y1.
	if _, err := db.Exec(`INSERT INTO routing_folders(id,name,priority,enabled) VALUES(1,'X',1,1),(2,'Y',3,1)`); err != nil {
		t.Fatalf("insert folders: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO routing_rules(priority,outbound_tag,match_json,folder_id) VALUES
        (1,'X1','{}',1),
        (2,'ung','{}',NULL),
        (1,'Y1','{}',2)`); err != nil {
		t.Fatalf("insert rules: %v", err)
	}
	// rules.priority for the ungrouped row uses GLOBAL slot — pick 2 to
	// land between Folder X (1) and Folder Y (3).
	got, _ := Load(db)
	if len(got) != 3 || got[0].OutboundTag != "X1" || got[1].OutboundTag != "ung" || got[2].OutboundTag != "Y1" {
		t.Fatalf("initial order wrong: %v", tags(got))
	}
	// "Drag Folder Y to position 1" → renumber: Y=1, X=2, ung stays 2
	// but folders/ungrouped tie-break by id; here ungrouped id=2 vs
	// folder Y id=2 — since they live in different tables the joined
	// id column is rules.id (=2 for ung, =3 for Y1). After change Y
	// (gp=1) Y1 ip=1 → comes first; X (gp=2) X1 ip=1 → second; ung
	// (gp=2 ip=0) → third (ip=0 < ip=1 means ung comes BEFORE X1, so
	// ungrouped wins the tie). To keep determinism we move ung to gp=3
	// to mirror operator intent.
	if _, err := db.Exec(`UPDATE routing_folders SET priority=1 WHERE id=2`); err != nil {
		t.Fatalf("upd Y: %v", err)
	}
	if _, err := db.Exec(`UPDATE routing_folders SET priority=2 WHERE id=1`); err != nil {
		t.Fatalf("upd X: %v", err)
	}
	if _, err := db.Exec(`UPDATE routing_rules SET priority=3 WHERE outbound_tag='ung'`); err != nil {
		t.Fatalf("upd ung: %v", err)
	}
	got, err := Load(db)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"Y1", "X1", "ung"}
	if len(got) != len(want) {
		t.Fatalf("want %d, got %d (%v)", len(want), len(got), tags(got))
	}
	for i, w := range want {
		if got[i].OutboundTag != w {
			t.Errorf("position %d: want %q, got %q", i, w, got[i].OutboundTag)
		}
	}
}

// TestLoadHierarchical_BackwardCompatLegacySchema verifies that an
// old-shape DB (no routing_folders table, no folder_id column) still
// loads correctly via the flat fallback path.
func TestLoadHierarchical_BackwardCompatLegacySchema(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO routing_rules(priority,outbound_tag,match_json) VALUES
        (1,'a','{}'),(2,'b','{}'),(3,'c','{}')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := Load(db)
	if err != nil {
		t.Fatalf("Load (legacy): %v", err)
	}
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("want %d, got %d (%v)", len(want), len(got), tags(got))
	}
	for i, w := range want {
		if got[i].OutboundTag != w {
			t.Errorf("legacy position %d: want %q, got %q", i, w, got[i].OutboundTag)
		}
	}
}

// TestLoadHierarchical_EmptyDB verifies graceful handling of a folders
// schema with zero rows.
func TestLoadHierarchical_EmptyDB(t *testing.T) {
	db := openTestDBWithFolders(t)
	defer db.Close()
	got, err := Load(db)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0, got %d (%v)", len(got), tags(got))
	}
}

func tags(rules []Loaded) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.OutboundTag
	}
	return out
}
