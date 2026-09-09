package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
)

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type psqlManagedLog struct {
	conn  *sql.DB
	table string
}

// NewPSQLManagedLogStore returns an implementation of the ManagedLogStore
// interface backed by the given `conn` to a PostgreSQL database.
//
// `table` is the name of the table to use, which will be created if it does not
// exist already.
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
		return 0, fmt.Errorf("stored version is out of range: %v", prev)
	}

	return int(prev), nil
}
