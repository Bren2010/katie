package db

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	// keyAttribute is the string partition key that holds the key.
	keyAttribute = "Key"
	// valueAttribute is the binary attribute that holds the value.
	valueAttribute = "Value"

	// labelAttribute is the binary partition key that holds the label.
	labelAttribute = "Label"
	// versionAttribute is the number that holds the greatest version of the
	// label that exists.
	versionAttribute = "Version"

	// ddbBatchGetLimit and ddbBatchWriteLimit are the number of items that
	// DynamoDB accepts in a single BatchGetItem or BatchWriteItem request.
	ddbBatchGetLimit   = 100
	ddbBatchWriteLimit = 25
)

// newDynamoDBTable connects to DynamoDB with the default AWS configuration,
// which is read from the usual environment variables, shared config files, and
// instance credentials. It creates `table` with a single partition key named
// `key` if the table does not exist already.
func newDynamoDBTable(
	ctx context.Context,
	table, key string,
	keyType types.ScalarAttributeType,
) (*dynamodb.Client, error) {
	if table == "" {
		return nil, errors.New("no table name provided")
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	client := dynamodb.NewFromConfig(cfg)

	_, err = client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(table),
		AttributeDefinitions: []types.AttributeDefinition{{
			AttributeName: aws.String(key),
			AttributeType: keyType,
		}},
		KeySchema: []types.KeySchemaElement{{
			AttributeName: aws.String(key),
			KeyType:       types.KeyTypeHash,
		}},
		BillingMode: types.BillingModePayPerRequest,
	})
	var inUse *types.ResourceInUseException
	if err != nil && !errors.As(err, &inUse) {
		return nil, err
	}

	// Tables are created asynchronously, so wait for it to become active.
	describe := &dynamodb.DescribeTableInput{TableName: aws.String(table)}
	if err := dynamodb.NewTableExistsWaiter(client).Wait(ctx, describe, time.Minute); err != nil {
		return nil, err
	}

	return client, nil
}

// ddbBackoff pauses briefly before asking DynamoDB again for the items that it
// didn't get to on the previous request.
func ddbBackoff(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(50 * time.Millisecond):
		return nil
	}
}

type ddbKeyValue struct {
	client *dynamodb.Client
	table  string
}

// NewDynamoDBKeyValueStore returns an implementation of the KeyValueStore
// interface backed by Amazon DynamoDB. It connects with the default AWS
// configuration, which is read from the usual environment variables, shared
// config files, and instance credentials.
//
// `table` is the name of the table to use, which will be created if it does not
// exist already.
func NewDynamoDBKeyValueStore(ctx context.Context, table string) (KeyValueStore, error) {
	client, err := newDynamoDBTable(ctx, table, keyAttribute, types.ScalarAttributeTypeS)
	if err != nil {
		return nil, err
	}
	return ddbKeyValue{client, table}, nil
}

func (kv ddbKeyValue) BatchGet(ctx context.Context, keys []string) ([][]byte, error) {
	// Deduplicate the keys, both because DynamoDB rejects a request that asks
	// for the same key twice, and because results come back in no particular
	// order and have to be matched up by key anyway.
	unique := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			unique = append(unique, key)
		}
	}

	found := make(map[string][]byte, len(unique))
	for chunk := range slices.Chunk(unique, ddbBatchGetLimit) {
		req := make([]map[string]types.AttributeValue, len(chunk))
		for i, key := range chunk {
			req[i] = map[string]types.AttributeValue{
				keyAttribute: &types.AttributeValueMemberS{Value: key},
			}
		}

		for len(req) > 0 {
			out, err := kv.client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
				RequestItems: map[string]types.KeysAndAttributes{
					kv.table: {Keys: req},
				},
			})
			if err != nil {
				return nil, err
			}
			for _, item := range out.Responses[kv.table] {
				key, ok := item[keyAttribute].(*types.AttributeValueMemberS)
				if !ok {
					return nil, errors.New("key attribute is not a string")
				}
				value, ok := item[valueAttribute].(*types.AttributeValueMemberB)
				if !ok {
					return nil, errors.New("value attribute is not binary")
				}
				found[key.Value] = value.Value
			}

			// DynamoDB returns the keys that it didn't get to, which have to be
			// requested again. The context bounds how long this can go on for.
			req = out.UnprocessedKeys[kv.table].Keys
			if len(req) > 0 {
				if err := ddbBackoff(ctx); err != nil {
					return nil, err
				}
			}
		}
	}

	out := make([][]byte, len(keys))
	for i, key := range keys {
		out[i] = found[key]
	}
	return out, nil
}

func (kv ddbKeyValue) Commit(ctx context.Context, batch map[string][]byte, treeHead []byte) error {
	// DynamoDB can not write this many items as one transaction, so the batch is
	// written first and the tree head afterwards. Interrupting that leaves
	// key-value pairs that no tree head refers to yet, which is recoverable. The
	// opposite order would not be.
	writes := make([]types.WriteRequest, 0, len(batch))
	for key, value := range batch {
		item := map[string]types.AttributeValue{
			keyAttribute: &types.AttributeValueMemberS{Value: key},
		}
		if value == nil {
			writes = append(writes, types.WriteRequest{
				DeleteRequest: &types.DeleteRequest{Key: item},
			})
		} else {
			item[valueAttribute] = &types.AttributeValueMemberB{Value: value}
			writes = append(writes, types.WriteRequest{
				PutRequest: &types.PutRequest{Item: item},
			})
		}
	}

	for chunk := range slices.Chunk(writes, ddbBatchWriteLimit) {
		req := chunk
		for len(req) > 0 {
			out, err := kv.client.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
				RequestItems: map[string][]types.WriteRequest{kv.table: req},
			})
			if err != nil {
				return err
			}

			req = out.UnprocessedItems[kv.table]
			if len(req) > 0 {
				if err := ddbBackoff(ctx); err != nil {
					return err
				}
			}
		}
	}

	_, err := kv.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(kv.table),
		Item: map[string]types.AttributeValue{
			keyAttribute:   &types.AttributeValueMemberS{Value: treeHeadKey},
			valueAttribute: &types.AttributeValueMemberB{Value: treeHead},
		},
	})
	return err
}

type ddbManagedLog struct {
	client *dynamodb.Client
	table  string
}

// NewDynamoDBManagedLogStore returns an implementation of the ManagedLogStore
// interface backed by Amazon DynamoDB. It connects with the default AWS
// configuration, which is read from the usual environment variables, shared
// config files, and instance credentials.
//
// `table` is the name of the table to use, which will be created if it does not
// exist already.
func NewDynamoDBManagedLogStore(ctx context.Context, table string) (ManagedLogStore, error) {
	client, err := newDynamoDBTable(ctx, table, labelAttribute, types.ScalarAttributeTypeB)
	if err != nil {
		return nil, err
	}
	return ddbManagedLog{client, table}, nil
}

func (ml ddbManagedLog) IncrementGreatestVersion(ctx context.Context, label []byte, count int) (int, error) {
	if count < 1 {
		return 0, errors.New("count must be greater than or equal to 1")
	} else if int64(count) > maxVersion {
		return 0, errors.New("count is greater than the maximum version")
	} else if len(label) == 0 {
		return 0, errors.New("label must not be empty")
	}

	// Treating a missing counter as -1 means that a label which doesn't exist
	// yet returns -1 and is left at count-1. The condition rejects the update if
	// it would push the counter to the maximum version or beyond, which keeps
	// the check atomic with the increment.
	limit := int64(1)<<32 - int64(count)

	out, err := ml.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(ml.table),
		Key: map[string]types.AttributeValue{
			labelAttribute: &types.AttributeValueMemberB{Value: label},
		},
		UpdateExpression:         aws.String("SET #v = if_not_exists(#v, :init) + :count"),
		ConditionExpression:      aws.String("attribute_not_exists(#v) OR #v < :limit"),
		ExpressionAttributeNames: map[string]string{"#v": versionAttribute},
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
			return 0, errors.New("increasing label version would exceed maximum")
		}
		return 0, err
	}

	// No attributes are returned when the item didn't exist previously, which
	// means no version of the label has been created yet.
	raw, ok := out.Attributes[versionAttribute].(*types.AttributeValueMemberN)
	if !ok {
		return -1, nil
	}
	prev, err := strconv.ParseInt(raw.Value, 10, 64)
	if err != nil {
		return 0, err
	} else if prev < -1 || prev > maxVersion {
		return 0, errors.New("stored version is out of range")
	}

	return int(prev), nil
}
