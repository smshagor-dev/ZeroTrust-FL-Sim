package coordinator

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestS3ArtifactStoreRejectsPlaintextEndpointByDefault(t *testing.T) {
	_, err := NewS3ModelArtifactStore(S3ArtifactStoreConfig{
		EndpointURL:     "http://127.0.0.1:9000",
		Bucket:          "ztfl-models",
		AccessKeyID:     "test-access",
		SecretAccessKey: "test-secret",
	})
	if err == nil || !strings.Contains(err.Error(), "insecure HTTP") {
		t.Fatalf("plaintext S3 endpoint error = %v, want explicit opt-in rejection", err)
	}
}

func TestS3ArtifactStoreValidatesEndpointBucketPrefixAndCredentials(t *testing.T) {
	tests := []struct {
		name string
		cfg  S3ArtifactStoreConfig
	}{
		{
			name: "endpoint path",
			cfg: S3ArtifactStoreConfig{
				EndpointURL: "https://s3.example.test/path",
				Bucket:      "ztfl-models", AccessKeyID: "a", SecretAccessKey: "b",
			},
		},
		{
			name: "uppercase bucket",
			cfg: S3ArtifactStoreConfig{
				EndpointURL: "https://s3.example.test",
				Bucket:      "ZTFL-models", AccessKeyID: "a", SecretAccessKey: "b",
			},
		},
		{
			name: "noncanonical prefix",
			cfg: S3ArtifactStoreConfig{
				EndpointURL: "https://s3.example.test",
				Bucket:      "ztfl-models", Prefix: "models/../escape", AccessKeyID: "a", SecretAccessKey: "b",
			},
		},
		{
			name: "missing credentials",
			cfg: S3ArtifactStoreConfig{
				EndpointURL: "https://s3.example.test",
				Bucket:      "ztfl-models",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewS3ModelArtifactStore(test.cfg); err == nil {
				t.Fatal("invalid S3 artifact configuration was accepted")
			}
		})
	}
}

func TestS3ArtifactStoreContentAddressedReferenceConfinement(t *testing.T) {
	store, err := NewS3ModelArtifactStore(S3ArtifactStoreConfig{
		EndpointURL:     "https://s3.example.test",
		Bucket:          "ztfl-models",
		Prefix:          "coordinator/models",
		AccessKeyID:     "test-access",
		SecretAccessKey: "test-secret",
	})
	if err != nil {
		t.Fatalf("create S3 artifact store: %v", err)
	}
	digest := sha256.Sum256([]byte("model"))
	ref := store.referenceForDigest(digest[:], 5)
	if err := store.validateReference(ref); err != nil {
		t.Fatalf("valid content-addressed reference rejected: %v", err)
	}

	traversal := ref
	traversal.Key = "coordinator/models/sha256/../secret"
	if err := store.validateReference(traversal); err == nil {
		t.Fatal("non-content-addressed artifact key was accepted")
	}

	wrongBucket := ref
	wrongBucket.Bucket = "other-bucket"
	if err := store.validateReference(wrongBucket); err == nil {
		t.Fatal("artifact reference for another bucket was accepted")
	}

	wrongDigest := ref
	wrongDigest.SHA256 = []byte{1, 2, 3}
	if err := store.validateReference(wrongDigest); err == nil {
		t.Fatal("artifact reference with malformed digest was accepted")
	}
}

func TestS3ArtifactStoreRejectsEmptyPayloadBeforeNetworkAccess(t *testing.T) {
	store, err := NewS3ModelArtifactStore(S3ArtifactStoreConfig{
		EndpointURL:       "http://127.0.0.1:1",
		Bucket:            "ztfl-models",
		Prefix:            "models",
		AccessKeyID:       "test-access",
		SecretAccessKey:   "test-secret",
		AllowInsecureHTTP: true,
		ForcePathStyle:    true,
	})
	if err != nil {
		t.Fatalf("create local S3 artifact store: %v", err)
	}
	if _, err := store.Put(context.Background(), nil); err == nil {
		t.Fatal("empty model artifact payload was accepted")
	}
}
