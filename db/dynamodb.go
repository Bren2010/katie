package db

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	// labelAttribute is the binary partition key that holds the label.
	labelAttribute = "Label"
	// versionAttribute is the number that holds the greatest version of the
	// label that exists.
	versionAttribute = "Version"
)

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
			AttributeName: aws.String(labelAttribute),
			AttributeType: types.ScalarAttributeTypeB,
		}},
		KeySchema: []types.KeySchemaElement{{
			AttributeName: aws.String(labelAttribute),
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
		return 0, fmt.Errorf("stored version is out of range: %v", prev)
	}

	return int(prev), nil
}
