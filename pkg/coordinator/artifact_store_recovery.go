package coordinator

import (
	"context"
	"errors"
	"fmt"

	"github.com/minio/minio-go/v7"
)

// RecoveryNamespaceEmpty reports whether the configured content-addressed
// model namespace contains any objects. Restore uses this before writing a
// bundle so a dirty target can never be silently mixed with recovered state.
func (s *S3ModelArtifactStore) RecoveryNamespaceEmpty(ctx context.Context) (bool, error) {
	if s == nil || s.client == nil {
		return false, errors.New("S3 model artifact store is nil")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	prefix := s.prefix + "/"
	for object := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if object.Err != nil {
			return false, fmt.Errorf("list recovery S3 namespace: %w", object.Err)
		}
		return false, nil
	}
	return true, nil
}
