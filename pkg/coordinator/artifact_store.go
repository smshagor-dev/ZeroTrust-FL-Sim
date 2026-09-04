package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"strings"
	"sync"
	"unicode"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var ErrArtifactNotFound = errors.New("model artifact not found")

type ModelArtifactRef struct {
	Bucket    string
	Key       string
	SHA256    []byte
	SizeBytes int64
}

type ModelArtifactStore interface {
	Put(context.Context, []byte) (ModelArtifactRef, error)
	Get(context.Context, ModelArtifactRef) ([]byte, error)
}

type S3ArtifactStoreConfig struct {
	EndpointURL       string
	Bucket            string
	Prefix            string
	Region            string
	AccessKeyID       string
	SecretAccessKey   string
	SessionToken      string
	AllowInsecureHTTP bool
	ForcePathStyle    bool
}

type S3ModelArtifactStore struct {
	client   *minio.Client
	bucket   string
	prefix   string
	verified sync.Map
}

func NewS3ModelArtifactStore(cfg S3ArtifactStoreConfig) (*S3ModelArtifactStore, error) {
	endpoint, secure, err := parseS3Endpoint(cfg.EndpointURL, cfg.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	bucket := strings.TrimSpace(cfg.Bucket)
	if err := validateS3BucketName(bucket); err != nil {
		return nil, err
	}
	prefix, err := normalizeArtifactPrefix(cfg.Prefix)
	if err != nil {
		return nil, err
	}
	accessKey := strings.TrimSpace(cfg.AccessKeyID)
	secretKey := strings.TrimSpace(cfg.SecretAccessKey)
	if accessKey == "" || secretKey == "" {
		return nil, errors.New("S3 access key ID and secret access key are required")
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = "us-east-1"
	}
	lookup := minio.BucketLookupAuto
	if cfg.ForcePathStyle {
		lookup = minio.BucketLookupPath
	}
	client, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, cfg.SessionToken),
		Secure:       secure,
		Region:       region,
		BucketLookup: lookup,
	})
	if err != nil {
		return nil, fmt.Errorf("configure S3-compatible artifact client: %w", err)
	}
	return &S3ModelArtifactStore{client: client, bucket: bucket, prefix: prefix}, nil
}

func (s *S3ModelArtifactStore) Put(ctx context.Context, payload []byte) (ModelArtifactRef, error) {
	if s == nil || s.client == nil {
		return ModelArtifactRef{}, errors.New("S3 model artifact store is nil")
	}
	if err := ctx.Err(); err != nil {
		return ModelArtifactRef{}, err
	}
	if len(payload) == 0 {
		return ModelArtifactRef{}, errors.New("model artifact payload is empty")
	}
	if len(payload) > maxCoordinatorStateBytes {
		return ModelArtifactRef{}, fmt.Errorf("model artifact exceeds %d bytes", maxCoordinatorStateBytes)
	}
	digest := sha256.Sum256(payload)
	ref := s.referenceForDigest(digest[:], int64(len(payload)))
	cacheKey := hex.EncodeToString(digest[:])
	if _, ok := s.verified.Load(cacheKey); ok {
		return ref, nil
	}

	info, err := s.client.StatObject(ctx, ref.Bucket, ref.Key, minio.StatObjectOptions{})
	if err == nil {
		if info.Size != ref.SizeBytes {
			return ModelArtifactRef{}, fmt.Errorf("existing model artifact %q has size %d, want %d", ref.Key, info.Size, ref.SizeBytes)
		}
		existing, getErr := s.Get(ctx, ref)
		if getErr != nil {
			return ModelArtifactRef{}, fmt.Errorf("verify existing model artifact %q: %w", ref.Key, getErr)
		}
		if !bytes.Equal(existing, payload) {
			return ModelArtifactRef{}, fmt.Errorf("existing model artifact %q does not match content-addressed payload", ref.Key)
		}
		s.verified.Store(cacheKey, struct{}{})
		return ref, nil
	}
	if !isS3NotFound(err) {
		return ModelArtifactRef{}, fmt.Errorf("inspect model artifact %q: %w", ref.Key, err)
	}

	upload, err := s.client.PutObject(ctx, ref.Bucket, ref.Key, bytes.NewReader(payload), ref.SizeBytes, minio.PutObjectOptions{
		ContentType:  networkWeightsFormat,
		UserMetadata: map[string]string{"sha256": cacheKey},
	})
	if err != nil {
		return ModelArtifactRef{}, fmt.Errorf("upload model artifact %q: %w", ref.Key, err)
	}
	if upload.Size != 0 && upload.Size != ref.SizeBytes {
		return ModelArtifactRef{}, fmt.Errorf("uploaded model artifact %q reports size %d, want %d", ref.Key, upload.Size, ref.SizeBytes)
	}
	s.verified.Store(cacheKey, struct{}{})
	return ref, nil
}

func (s *S3ModelArtifactStore) Get(ctx context.Context, ref ModelArtifactRef) ([]byte, error) {
	if s == nil || s.client == nil {
		return nil, errors.New("S3 model artifact store is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.validateReference(ref); err != nil {
		return nil, err
	}

	info, err := s.client.StatObject(ctx, ref.Bucket, ref.Key, minio.StatObjectOptions{})
	if err != nil {
		if isS3NotFound(err) {
			return nil, fmt.Errorf("%w: %s/%s", ErrArtifactNotFound, ref.Bucket, ref.Key)
		}
		return nil, fmt.Errorf("inspect model artifact %q: %w", ref.Key, err)
	}
	if info.Size != ref.SizeBytes {
		return nil, fmt.Errorf("model artifact %q has size %d, want %d", ref.Key, info.Size, ref.SizeBytes)
	}

	object, err := s.client.GetObject(ctx, ref.Bucket, ref.Key, minio.GetObjectOptions{})
	if err != nil {
		if isS3NotFound(err) {
			return nil, fmt.Errorf("%w: %s/%s", ErrArtifactNotFound, ref.Bucket, ref.Key)
		}
		return nil, fmt.Errorf("open model artifact %q: %w", ref.Key, err)
	}
	defer object.Close()

	data, err := io.ReadAll(io.LimitReader(object, ref.SizeBytes+1))
	if err != nil {
		if isS3NotFound(err) {
			return nil, fmt.Errorf("%w: %s/%s", ErrArtifactNotFound, ref.Bucket, ref.Key)
		}
		return nil, fmt.Errorf("read model artifact %q: %w", ref.Key, err)
	}
	if int64(len(data)) != ref.SizeBytes {
		return nil, fmt.Errorf("model artifact %q read %d bytes, want %d", ref.Key, len(data), ref.SizeBytes)
	}
	digest := sha256.Sum256(data)
	if !bytes.Equal(digest[:], ref.SHA256) {
		return nil, fmt.Errorf("model artifact %q SHA-256 digest mismatch", ref.Key)
	}
	s.verified.Store(hex.EncodeToString(digest[:]), struct{}{})
	return data, nil
}

func (s *S3ModelArtifactStore) referenceForDigest(digest []byte, size int64) ModelArtifactRef {
	hexDigest := hex.EncodeToString(digest)
	return ModelArtifactRef{
		Bucket:    s.bucket,
		Key:       s.prefix + "/sha256/" + hexDigest + ".npy",
		SHA256:    append([]byte(nil), digest...),
		SizeBytes: size,
	}
}

func (s *S3ModelArtifactStore) validateReference(ref ModelArtifactRef) error {
	if ref.Bucket != s.bucket {
		return fmt.Errorf("model artifact bucket %q does not match configured bucket", ref.Bucket)
	}
	if len(ref.SHA256) != sha256.Size {
		return errors.New("model artifact reference requires a 32-byte SHA-256 digest")
	}
	if ref.SizeBytes <= 0 || ref.SizeBytes > maxCoordinatorStateBytes {
		return fmt.Errorf("model artifact reference has invalid size %d", ref.SizeBytes)
	}
	expected := s.referenceForDigest(ref.SHA256, ref.SizeBytes)
	if ref.Key != expected.Key {
		return fmt.Errorf("model artifact key %q is outside the configured content-addressed namespace", ref.Key)
	}
	return nil
}

func parseS3Endpoint(raw string, allowInsecure bool) (string, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false, errors.New("S3 endpoint URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", false, fmt.Errorf("parse S3 endpoint URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", false, errors.New("S3 endpoint URL scheme must be https or http")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false, errors.New("S3 endpoint URL must contain only scheme and host")
	}
	if parsed.Scheme == "http" && !allowInsecure {
		return "", false, errors.New("plaintext S3 endpoint requires explicit insecure HTTP opt-in")
	}
	return parsed.Host, parsed.Scheme == "https", nil
}

func validateS3BucketName(bucket string) error {
	if len(bucket) < 3 || len(bucket) > 63 {
		return errors.New("S3 bucket name must contain 3 to 63 characters")
	}
	if net.ParseIP(bucket) != nil {
		return errors.New("S3 bucket name must not be formatted as an IP address")
	}
	if bucket[0] < 'a' || bucket[0] > 'z' {
		if bucket[0] < '0' || bucket[0] > '9' {
			return errors.New("S3 bucket name must start with a lowercase letter or digit")
		}
	}
	last := bucket[len(bucket)-1]
	if !((last >= 'a' && last <= 'z') || (last >= '0' && last <= '9')) {
		return errors.New("S3 bucket name must end with a lowercase letter or digit")
	}
	for _, r := range bucket {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-') {
			return errors.New("S3 bucket name contains an unsupported character")
		}
	}
	if strings.Contains(bucket, "..") || strings.Contains(bucket, ".-") || strings.Contains(bucket, "-.") {
		return errors.New("S3 bucket name contains an invalid adjacent separator")
	}
	return nil
}

func normalizeArtifactPrefix(raw string) (string, error) {
	trimmed := strings.Trim(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		trimmed = "models"
	}
	if strings.Contains(trimmed, "\\") {
		return "", errors.New("S3 artifact prefix must use forward slashes")
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return "", errors.New("S3 artifact prefix must not contain control characters")
		}
	}
	cleaned := path.Clean(trimmed)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != trimmed {
		return "", errors.New("S3 artifact prefix must be a canonical relative object prefix")
	}
	return cleaned, nil
}

func isS3NotFound(err error) bool {
	if err == nil {
		return false
	}
	response := minio.ToErrorResponse(err)
	return response.StatusCode == 404 || response.Code == "NoSuchKey" || response.Code == "NoSuchObject" || response.Code == "NotFound"
}
