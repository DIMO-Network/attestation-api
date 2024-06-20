// Package indexfile contains service code for gettting and managing index files.
//
//go:generate mockgen -source=./indexfile.go -destination=indexfile_mock_test.go -package=indexfile_test
package indexfile

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/nameindexer"
	chindexer "github.com/DIMO-Network/nameindexer/pkg/clickhouse"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/s3"
)

// Service manages and retrieves data messages from index files in S3.
type Service struct {
	objGetter  ObjectGetter
	chConn     clickhouse.Conn
	dataType   string
	bucketName string
}

// ObjectGetter is an interface for getting an object from S3.
type ObjectGetter interface {
	GetObjectWithContext(ctx context.Context, input *s3.GetObjectInput, opts ...request.Option) (*s3.GetObjectOutput, error)
	PutObjectWithContext(ctx context.Context, input *s3.PutObjectInput, opts ...request.Option) (*s3.PutObjectOutput, error)
}

// New creates a new instance of IndexFileService.
func New(chConn clickhouse.Conn, objGetter ObjectGetter, bucketName, dataType string) *Service {
	return &Service{
		objGetter:  objGetter,
		chConn:     chConn,
		bucketName: bucketName,
		dataType:   dataType,
	}
}

// GetLatestFileName returns the latest filename for the given subject and data type.
func (s *Service) GetLatestFileName(ctx context.Context, subject nameindexer.Subject) (string, error) {
	query := fmt.Sprintf("SELECT argMax(%s, %s) AS filename FROM %s WHERE %s = ? AND %s = ?", chindexer.FileNameColumn, chindexer.TimestampColumn, chindexer.TableName, chindexer.SubjectColumn, chindexer.DataTypeColumn)

	var filename string
	err := s.chConn.QueryRow(ctx, query, subject, s.dataType).Scan(&filename)
	if err != nil {
		return "", fmt.Errorf("failed to get latest filename: %w", err)
	}
	if filename == "" {
		return "", fmt.Errorf("no filenames found for subject %w", sql.ErrNoRows)
	}
	return filename, nil
}

// GetLatestData fetches and returns the latest data for the given subject.
func (s *Service) GetLatestData(ctx context.Context, subject nameindexer.Subject) ([]byte, error) {
	filename, err := s.GetLatestFileName(ctx, subject)
	if err != nil {
		return nil, err
	}

	data, err := s.GetDataFromFile(ctx, filename)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// GetDataFromFile gets the data from S3 by filename.
func (s *Service) GetDataFromFile(ctx context.Context, filename string) ([]byte, error) {
	obj, err := s.objGetter.GetObjectWithContext(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(filename),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get object from S3: %w", err)
	}
	defer obj.Body.Close()

	data, err := io.ReadAll(obj.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read object body: %w", err)
	}
	return data, nil
}

// StoreFile stores the given data in S3 with the given index.
func (s *Service) StoreFile(ctx context.Context, index *nameindexer.Index, data []byte) error {
	fileName, err := nameindexer.EncodeIndex(index)
	if err != nil {
		return fmt.Errorf("failed to encode index: %w", err)
	}

	_, err = s.objGetter.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket: &s.bucketName,
		Key:    &fileName,
		Body:   aws.ReadSeekCloser(bytes.NewReader(data)),
	})
	if err != nil {
		return fmt.Errorf("failed to store object in S3: %w", err)
	}

	values, err := chindexer.IndexToSlice(index)
	if err != nil {
		return fmt.Errorf("failed to convert index to slice: %w", err)
	}
	var query strings.Builder
	query.WriteString(fmt.Sprintf("INSERT INTO %s VALUES (", chindexer.TableName)) //nolint:revive
	for i := range values {
		if i > 0 {
			query.WriteString(", ") //nolint:revive
		}
		query.WriteString("?") //nolint:revive
	}
	query.WriteString(")") //nolint:revive
	err = s.chConn.Exec(ctx, query.String(), values...)
	if err != nil {
		return fmt.Errorf("failed to store index in ClickHouse: %w", err)
	}

	return nil
}
