package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"regexp"
)

type psqlManagedLogStore struct {
	ctx   context.Context
	conn  *sql.DB
	table string
}

// NewPSQLManagedLogStore returns a ManagedLogStore backed by the given `conn`
// to a PostgreSQL database. `ctx` is used as the parent context for every
// query. `conn` may be opened with any PostgreSQL driver, and is not closed by
// this package. `table` is the name of the table to use.
//
// The table must already be created with the following schema:
func NewPSQLManagedLogStore(ctx context.Context, conn *sql.DB, table string) (ManagedLogStore, error) {
	if ctx == nil {
		return nil, errors.New("no context provided")
	} else if conn == nil {
		return nil, errors.New("no database connection provided")
	} else if !identifier.MatchString(table) {
		return nil, fmt.Errorf("table name is not a valid sql identifier: %v", table)
	}

	return &psqlManagedLogStore{
		ctx:   ctx,
		conn:  conn,
		table: table,
	}, nil
}

// // CreateTable provisions the store's table if it does not already exist.
// func (mls *ManagedLogStore) CreateTable() error {
// 	stmt, err := CreateTableStatement(mls.table)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = mls.conn.ExecContext(mls.ctx, stmt)
// 	return err
// }

func (mls *psqlManagedLogStore) IncrementGreatestVersion(label []byte, count int) (int, error) {
	if count < 1 {
		return 0, errors.New("count must be greater than or equal to 1")
	} else if int64(count) > int64(maxVersion) {
		return 0, errors.New("count is greater than the maximum version")
	}
	if label == nil {
		// A nil slice is stored as NULL, which the primary key rejects.
		label = []byte{}
	}

	var prev int64
	row := mls.conn.QueryRowContext(mls.ctx, mls.increment, label, int64(count))
	if err := row.Scan(&prev); errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("greatest version of label would exceed the maximum: %x", label)
	} else if err != nil {
		return 0, err
	} else if prev < -1 || prev > int64(maxVersion) || prev > math.MaxInt {
		return 0, fmt.Errorf("stored version is out of range: %v", prev)
	}

	return int(prev), nil
}

// // maxVersion is the greatest version number that the protocol can represent.
// // Versions are serialized as uint32, so allowing a counter past this point would
// // wrap around and cause the Service Operator to sign two different values under
// // the same version.
// const maxVersion = math.MaxUint32

// // createTableStmt is the schema that this package expects. It's exported through
// // CreateTableStatement for operators that manage their schema separately.
// const createTableStmt = `CREATE TABLE IF NOT EXISTS %s (
// 	label BYTEA PRIMARY KEY,
// 	version BIGINT NOT NULL CHECK (version >= 0 AND version <= %d)
// )`

// incrementStmt atomically increments the counter for a label and returns its
// previous value. The row is inserted with version = count-1 if the label is new,
// so that the statement returns -1 as required by the interface.
//
// The WHERE clause suppresses the update if it would push the counter past
// maxVersion, which makes the statement return no rows instead.
const incrementStmt = `INSERT INTO %s AS t (label, version)
VALUES ($1, $2::bigint - 1)
ON CONFLICT (label) DO UPDATE
	SET version = t.version + $2::bigint
	WHERE t.version + $2::bigint <= %d
RETURNING version - $2::bigint`

// identifier matches the SQL identifiers that this package is willing to
// interpolate into a query.
var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// CreateTableStatement returns the DDL that provisions `table` with the schema
// this package expects. It returns an error if `table` is not a plain SQL
// identifier.
func CreateTableStatement(table string) (string, error) {
	if !identifier.MatchString(table) {
		return "", fmt.Errorf("table name is not a valid sql identifier: %v", table)
	}
	return fmt.Sprintf(createTableStmt, table, int64(maxVersion)), nil
}
