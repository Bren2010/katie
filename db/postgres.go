package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

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
	}

	_, err := conn.Exec(`CREATE TABLE IF NOT EXISTS $1 (
		label BYTEA PRIMARY KEY,
		version BIGINT NOT NULL CHECK (version >= 0 AND version < $2)
	)`, table, 1<<32)
	if err != nil {
		return nil, err
	}

	return psqlManagedLog{conn, table}, nil
}

func (ml psqlManagedLog) IncrementGreatestVersion(ctx context.Context, label []byte, count int) (int, error) {
	if count < 1 {
		return 0, errors.New("count must be greater than or equal to 1")
	}

	row := ml.conn.QueryRowContext(ctx, `INSERT INTO $1 AS t (label, version)
		VALUES ($3, $4::bigint - 1)
		ON CONFLICT (label) DO UPDATE
			SET version = t.version + $4::bigint
			WHERE t.version + $4::bigint < $2
		RETURNING version - $4::bigint`, ml.table, 1<<32, label, int64(count))

	var prev int64
	if err := row.Scan(&prev); errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("increasing label version would exceed maximum")
	} else if err != nil {
		return 0, err
	} else if prev < -1 || prev >= int64(1)<<32 {
		return 0, fmt.Errorf("stored version is out of range: %v", prev)
	}

	return int(prev), nil
}
