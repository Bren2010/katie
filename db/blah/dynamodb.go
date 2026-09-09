package db

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/Bren2010/katie/db"
)

const (
	// labelAttribute is the binary partition key that holds the label.
	labelAttribute = "Label"
	// versionAttribute is the number that holds the greatest version of the
	// label that exists.
	versionAttribute = "Version"

	// maxVersion is the greatest version number that the protocol can
	// represent. Versions are serialized as uint32, so allowing a counter past
	// this point would wrap around and cause the Service Operator to sign two
	// different values under the same version.
	maxVersion = math.MaxUint32
)

// UpdateItemAPI is the subset of the DynamoDB client used by ManagedLogStore.
// It is satisfied by *dynamodb.Client from the AWS SDK.
type UpdateItemAPI interface {
	UpdateItem(
		ctx context.Context,
		params *awsddb.UpdateItemInput,
		optFns ...func(*awsddb.Options),
	) (*awsddb.UpdateItemOutput, error)
}

// CreateTableAPI is the subset of the DynamoDB client used by CreateTable. It is
// satisfied by *dynamodb.Client from the AWS SDK.
type CreateTableAPI interface {
	CreateTable(
		ctx context.Context,
		params *awsddb.CreateTableInput,
		optFns ...func(*awsddb.Options),
	) (*awsddb.CreateTableOutput, error)
}

// CreateTable provisions `table` with the schema this package expects: a single
// binary partition key named Label, billed on demand.
//
// DynamoDB creates tables asynchronously, so the table is not usable until it
// becomes ACTIVE. Callers that need to wait should use the SDK's
// TableExistsWaiter.
func CreateTable(ctx context.Context, client CreateTableAPI, table string) error {
	_, err := client.CreateTable(ctx, &awsddb.CreateTableInput{
		TableName: aws.String(table),
		AttributeDefinitions: []types.AttributeDefinition{{
			AttributeName: aws.String(labelAttribute),
			AttributeType: types.ScalarAttributeTypeB,
		}},
		KeySchema: []types.KeySchemaElement{{
			AttributeName: aws.String(labelAttribute),
			KeyType:       types.KeyTypeHash,
		}},
		BillingMode: types.BillingModePayPerRequest,
	})
	return err
}

// ManagedLogStore implements the db.ManagedLogStore interface over DynamoDB.
type ManagedLogStore struct {
	// ctx is the parent context for every request. The db.ManagedLogStore
	// interface has no way to pass a context per call, so one is provided when
	// the store is constructed instead.
	ctx    context.Context
	client UpdateItemAPI
	table  string
}

var _ db.ManagedLogStore = &ManagedLogStore{}

// NewManagedLogStore returns a ManagedLogStore that keeps its counters in
// `table`, which must already exist. Call CreateTable to provision it.
//
// `ctx` is used as the parent context for every request.
func NewManagedLogStore(ctx context.Context, client UpdateItemAPI, table string) (*ManagedLogStore, error) {
	if ctx == nil {
		return nil, errors.New("no context provided")
	} else if client == nil {
		return nil, errors.New("no dynamodb client provided")
	} else if table == "" {
		return nil, errors.New("no table name provided")
	}
	return &ManagedLogStore{ctx: ctx, client: client, table: table}, nil
}

func (mls *ManagedLogStore) IncrementGreatestVersion(label []byte, count int) (int, error) {
	if count < 1 {
		return 0, errors.New("count must be greater than or equal to 1")
	} else if int64(count) > int64(maxVersion) {
		return 0, errors.New("count is greater than the maximum version")
	} else if len(label) == 0 {
		// DynamoDB rejects an empty partition key value.
		return 0, errors.New("label must not be empty")
	}

	// Treating a missing counter as -1 makes the update return -1 for a label
	// that doesn't exist yet, and leaves it at count-1 afterwards.
	//
	// The condition suppresses the update if it would push the counter past
	// maxVersion. Evaluating it as part of the update keeps the check atomic.
	limit := int64(maxVersion) - int64(count)

	out, err := mls.client.UpdateItem(mls.ctx, &awsddb.UpdateItemInput{
		TableName: aws.String(mls.table),
		Key: map[string]types.AttributeValue{
			labelAttribute: &types.AttributeValueMemberB{Value: label},
		},
		UpdateExpression:    aws.String("SET #v = if_not_exists(#v, :init) + :count"),
		ConditionExpression: aws.String("attribute_not_exists(#v) OR #v <= :limit"),
		ExpressionAttributeNames: map[string]string{
			"#v": versionAttribute,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":init":  &types.AttributeValueMemberN{Value: "-1"},
			":count": &types.AttributeValueMemberN{Value: strconv.Itoa(count)},
			":limit": &types.AttributeValueMemberN{Value: strconv.FormatInt(limit, 10)},
		},
		ReturnValues: types.ReturnValueUpdatedOld,
	})
	if err != nil {
		var failed *types.ConditionalCheckFailedException
		if errors.As(err, &failed) {
			return 0, fmt.Errorf("greatest version of label would exceed the maximum: %x", label)
		}
		return 0, err
	}

	// UPDATED_OLD returns no attributes when the item didn't exist previously,
	// which means no version of the label has been created yet.
	raw, ok := out.Attributes[versionAttribute]
	if !ok {
		return -1, nil
	}
	num, ok := raw.(*types.AttributeValueMemberN)
	if !ok {
		return 0, fmt.Errorf("%v attribute is not a number", versionAttribute)
	}
	prev, err := strconv.ParseInt(num.Value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing %v attribute: %w", versionAttribute, err)
	} else if prev < -1 || prev > int64(maxVersion) || prev > math.MaxInt {
		return 0, fmt.Errorf("stored version is out of range: %v", prev)
	}

	return int(prev), nil
}
