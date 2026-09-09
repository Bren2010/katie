package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type psqlKeyValue struct {
	conn  *sql.DB
	table string
}

// NewPSQLKeyValueStore returns an implementation of the KeyValueStore interface
// backed by the given `conn` to a PostgreSQL database. `table` is the name of
// the table to use, which will be created if it does not exist already.
func NewPSQLKeyValueStore(conn *sql.DB, table string) (KeyValueStore, error) {
	if conn == nil {
		return nil, errors.New("no database connection provided")
	} else if !identifier.MatchString(table) {
		return nil, errors.New("table name is not a valid sql identifier")
	}

	_, err := conn.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (
		key TEXT PRIMARY KEY,
		value BYTEA
	)`, table))
	if err != nil {
		return nil, err
	}

	return psqlKeyValue{conn, table}, nil
}

func (kv psqlKeyValue) BatchGet(ctx context.Context, keys []string) ([][]byte, error) {
	out := make([][]byte, len(keys))
	if len(keys) == 0 {
		return out, nil
	}

	// Deduplicate the keys so that the query doesn't ask for the same row twice.
	// Rows come back in no particular order, so they're matched up by key.
	placeholders := make([]string, 0, len(keys))
	args := make([]any, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		args = append(args, key)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}

	rows, err := kv.conn.QueryContext(ctx, fmt.Sprintf(
		`SELECT key, value FROM %v WHERE key IN (%v)`,
		kv.table, strings.Join(placeholders, ",")), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	found := make(map[string][]byte, len(args))
	for rows.Next() {
		var key string
		var value []byte
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		found[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i, key := range keys {
		out[i] = found[key]
	}
	return out, nil
}

func (kv psqlKeyValue) Commit(ctx context.Context, batch map[string][]byte, treeHead []byte) error {
	// PostgreSQL can write the whole batch and the tree head as one transaction,
	// so either all of it lands or none of it does.
	tx, err := kv.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	upsert, err := tx.PrepareContext(ctx, fmt.Sprintf(
		`INSERT INTO %v (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, kv.table))
	if err != nil {
		return err
	}
	remove, err := tx.PrepareContext(ctx, fmt.Sprintf(
		`DELETE FROM %v WHERE key = $1`, kv.table))
	if err != nil {
		return err
	}

	for key, value := range batch {
		if value == nil {
			_, err = remove.ExecContext(ctx, key)
		} else {
			_, err = upsert.ExecContext(ctx, key, value)
		}
		if err != nil {
			return err
		}
	}
	if _, err := upsert.ExecContext(ctx, treeHeadKey, treeHead); err != nil {
		return err
	}

	return tx.Commit()
}

type psqlManagedLog struct {
	conn  *sql.DB
	table string
}

// NewPSQLManagedLogStore returns an implementation of the ManagedLogStore
// interface backed by the given `conn` to a PostgreSQL database. `table` is the
// name of the table to use, which will be created if it does not exist already.
func NewPSQLManagedLogStore(conn *sql.DB, table string) (ManagedLogStore, error) {
	if conn == nil {
		return nil, errors.New("no database connection provided")
	} else if !identifier.MatchString(table) {
		return nil, errors.New("table name is not a valid sql identifier")
	}

	_, err := conn.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (
		label BYTEA PRIMARY KEY,
		version BIGINT NOT NULL CHECK (version >= 0 AND version <= %d)
	)`, table, maxVersion))
	if err != nil {
		return nil, err
	}

	return psqlManagedLog{conn, table}, nil
}

func (ml psqlManagedLog) IncrementGreatestVersion(ctx context.Context, label []byte, count int) (int, error) {
	if count < 1 {
		return 0, errors.New("count must be greater than or equal to 1")
	} else if int64(count) > maxVersion {
		return 0, errors.New("count is greater than the maximum version")
	} else if len(label) == 0 {
		return 0, errors.New("label must not be empty")
	}

	row := ml.conn.QueryRowContext(ctx, fmt.Sprintf(`INSERT INTO %v AS t (label, version)
		VALUES ($1, $2::bigint - 1)
		ON CONFLICT (label) DO UPDATE
			SET version = t.version + $2::bigint
			WHERE t.version + $2::bigint <= %d
		RETURNING version - $2::bigint`, ml.table, maxVersion), label, int64(count))

	var prev int64
	if err := row.Scan(&prev); errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("increasing label version would exceed maximum")
	} else if err != nil {
		return 0, err
	} else if prev < -1 || prev > maxVersion {
		return 0, errors.New("stored version is out of range")
	}

	return int(prev), nil
}
