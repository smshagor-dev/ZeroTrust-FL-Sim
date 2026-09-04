package recovery

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	BundleSchemaVersion = 1
	manifestFileName    = "manifest.json"
	manifestChecksum   = "manifest.sha256"
	postgresDumpPath   = "postgres.dump"
	auditExportPath    = "audit.ndjson"
	maxManifestBytes   = 1 << 20
)

type MigrationManifest struct {
	Version int    `json:"version"`
	Name    string `json:"name"`
}

type FileManifest struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type DatabaseManifest struct {
	PostgreSQLVersion    string              `json:"postgresql_version"`
	PostgreSQLVersionNum int                 `json:"postgresql_version_num"`
	StateSchemaVersion   int                 `json:"state_schema_version"`
	ModelVersion         string              `json:"model_version"`
	RoundID              uint64              `json:"round_id"`
	Migrations           []MigrationManifest `json:"migrations"`
	Dump                 FileManifest        `json:"dump"`
}

type ArtifactManifest struct {
	Bucket    string       `json:"bucket"`
	Key       string       `json:"key"`
	SHA256    string       `json:"sha256"`
	SizeBytes int64        `json:"size_bytes"`
	File      FileManifest `json:"file"`
}

type AuditManifest struct {
	HeadSequence int64        `json:"head_sequence"`
	HeadHash     string       `json:"head_hash,omitempty"`
	File         FileManifest `json:"file"`
}

type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	CreatedAt     time.Time         `json:"created_at"`
	Database      DatabaseManifest  `json:"database"`
	Artifact      *ArtifactManifest `json:"artifact,omitempty"`
	Audit         AuditManifest     `json:"audit"`
}

func NewManifest(createdAt time.Time) Manifest {
	return Manifest{
		SchemaVersion: BundleSchemaVersion,
		CreatedAt:     createdAt.UTC().Truncate(time.Microsecond),
	}
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != BundleSchemaVersion {
		return fmt.Errorf("unsupported recovery bundle schema version %d", m.SchemaVersion)
	}
	if m.CreatedAt.IsZero() || m.CreatedAt.Location() != time.UTC || !m.CreatedAt.Equal(m.CreatedAt.Truncate(time.Microsecond)) {
		return errors.New("recovery bundle created_at must use UTC microsecond precision")
	}
	if strings.TrimSpace(m.Database.PostgreSQLVersion) == "" || m.Database.PostgreSQLVersionNum <= 0 {
		return errors.New("recovery bundle PostgreSQL version metadata is incomplete")
	}
	if m.Database.StateSchemaVersion <= 0 || strings.TrimSpace(m.Database.ModelVersion) == "" {
		return errors.New("recovery bundle coordinator state metadata is incomplete")
	}
	if len(m.Database.Migrations) == 0 {
		return errors.New("recovery bundle migration ledger is empty")
	}
	previousVersion := 0
	for _, migration := range m.Database.Migrations {
		if migration.Version <= previousVersion {
			return errors.New("recovery bundle migrations must be strictly increasing")
		}
		if strings.TrimSpace(migration.Name) == "" || len(migration.Name) > 256 || strings.ContainsAny(migration.Name, "/\\\x00\r\n") {
			return fmt.Errorf("recovery bundle migration %d has an invalid name", migration.Version)
		}
		previousVersion = migration.Version
	}
	if err := validateFileManifest(m.Database.Dump, postgresDumpPath, false); err != nil {
		return fmt.Errorf("validate PostgreSQL dump manifest: %w", err)
	}
	if err := validateFileManifest(m.Audit.File, auditExportPath, true); err != nil {
		return fmt.Errorf("validate audit export manifest: %w", err)
	}
	if m.Audit.HeadSequence < 0 {
		return errors.New("recovery audit head sequence must not be negative")
	}
	if m.Audit.HeadSequence == 0 {
		if m.Audit.HeadHash != "" {
			return errors.New("empty recovery audit chain must not have a head hash")
		}
	} else if err := validateSHA256Hex(m.Audit.HeadHash); err != nil {
		return fmt.Errorf("validate recovery audit head hash: %w", err)
	}

	if m.Artifact != nil {
		if strings.TrimSpace(m.Artifact.Bucket) == "" || strings.TrimSpace(m.Artifact.Key) == "" {
			return errors.New("recovery artifact bucket and key are required")
		}
		if strings.ContainsAny(m.Artifact.Bucket+m.Artifact.Key, "\x00\r\n") {
			return errors.New("recovery artifact reference contains control characters")
		}
		if err := validateSHA256Hex(m.Artifact.SHA256); err != nil {
			return fmt.Errorf("validate recovery artifact digest: %w", err)
		}
		if m.Artifact.SizeBytes <= 0 {
			return errors.New("recovery artifact size must be positive")
		}
		expectedPath := "artifacts/sha256/" + m.Artifact.SHA256 + ".npy"
		if err := validateFileManifest(m.Artifact.File, expectedPath, false); err != nil {
			return fmt.Errorf("validate recovery artifact file: %w", err)
		}
		if m.Artifact.File.SHA256 != m.Artifact.SHA256 || m.Artifact.File.SizeBytes != m.Artifact.SizeBytes {
			return errors.New("recovery artifact file digest/size disagrees with artifact reference")
		}
	}
	return nil
}

func validateFileManifest(file FileManifest, expectedPath string, allowEmpty bool) error {
	if file.Path != expectedPath {
		return fmt.Errorf("path %q does not match required path %q", file.Path, expectedPath)
	}
	if err := validateRelativePath(file.Path); err != nil {
		return err
	}
	if err := validateSHA256Hex(file.SHA256); err != nil {
		return err
	}
	if file.SizeBytes < 0 || (!allowEmpty && file.SizeBytes == 0) {
		return errors.New("recovery file has an invalid size")
	}
	return nil
}

func validateRelativePath(value string) error {
	if value == "" || filepath.IsAbs(value) || strings.Contains(value, "\\") {
		return errors.New("recovery bundle path must be a canonical relative forward-slash path")
	}
	cleaned := filepath.ToSlash(filepath.Clean(value))
	if cleaned != value || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return errors.New("recovery bundle path is not canonical")
	}
	return nil
}

func validateSHA256Hex(value string) error {
	if value == "" || value != strings.ToLower(value) {
		return errors.New("SHA-256 digest must be lowercase hexadecimal")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("SHA-256 digest must encode exactly 32 bytes")
	}
	return nil
}

func CanonicalManifestJSON(manifest Manifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode recovery bundle manifest: %w", err)
	}
	return append(data, '\n'), nil
}

func WriteManifest(root string, manifest Manifest) error {
	data, err := CanonicalManifestJSON(manifest)
	if err != nil {
		return err
	}
	if len(data) > maxManifestBytes {
		return errors.New("recovery bundle manifest exceeds size limit")
	}
	if err := os.WriteFile(filepath.Join(root, manifestFileName), data, 0o600); err != nil {
		return fmt.Errorf("write recovery bundle manifest: %w", err)
	}
	digest := sha256.Sum256(data)
	checksum := hex.EncodeToString(digest[:]) + "  " + manifestFileName + "\n"
	if err := os.WriteFile(filepath.Join(root, manifestChecksum), []byte(checksum), 0o600); err != nil {
		return fmt.Errorf("write recovery bundle manifest checksum: %w", err)
	}
	return nil
}

func LoadManifest(root string) (Manifest, error) {
	manifestPath, err := safeBundleFile(root, manifestFileName)
	if err != nil {
		return Manifest{}, err
	}
	checksumPath, err := safeBundleFile(root, manifestChecksum)
	if err != nil {
		return Manifest{}, err
	}
	data, err := readBoundedFile(manifestPath, maxManifestBytes)
	if err != nil {
		return Manifest{}, fmt.Errorf("read recovery bundle manifest: %w", err)
	}
	checksumData, err := readBoundedFile(checksumPath, 256)
	if err != nil {
		return Manifest{}, fmt.Errorf("read recovery bundle manifest checksum: %w", err)
	}
	digest := sha256.Sum256(data)
	expected := hex.EncodeToString(digest[:]) + "  " + manifestFileName + "\n"
	if string(checksumData) != expected {
		return Manifest{}, errors.New("recovery bundle manifest checksum mismatch")
	}

	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode recovery bundle manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Manifest{}, errors.New("recovery bundle manifest contains trailing JSON values")
		}
		return Manifest{}, fmt.Errorf("decode trailing recovery bundle manifest data: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, fmt.Errorf("validate recovery bundle manifest: %w", err)
	}
	return manifest, nil
}

func DigestFile(root, relativePath string) (FileManifest, error) {
	if err := validateRelativePath(relativePath); err != nil {
		return FileManifest{}, err
	}
	path, err := safeBundleFile(root, relativePath)
	if err != nil {
		return FileManifest{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return FileManifest{}, fmt.Errorf("open recovery bundle file %q: %w", relativePath, err)
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, bufio.NewReader(file))
	if err != nil {
		return FileManifest{}, fmt.Errorf("hash recovery bundle file %q: %w", relativePath, err)
	}
	return FileManifest{Path: relativePath, SHA256: hex.EncodeToString(hash.Sum(nil)), SizeBytes: size}, nil
}

func VerifyFile(root string, expected FileManifest) error {
	actual, err := DigestFile(root, expected.Path)
	if err != nil {
		return err
	}
	if actual.SizeBytes != expected.SizeBytes || actual.SHA256 != expected.SHA256 {
		return fmt.Errorf("recovery bundle file %q digest/size mismatch", expected.Path)
	}
	return nil
}

func safeBundleFile(root, relativePath string) (string, error) {
	if err := validateRelativePath(relativePath); err != nil {
		return "", err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("inspect recovery bundle root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", errors.New("recovery bundle root must be a real directory")
	}
	candidate := filepath.Join(root, filepath.FromSlash(relativePath))
	info, err := os.Lstat(candidate)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("recovery bundle path %q must be a regular non-symlink file", relativePath)
	}
	return candidate, nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return data, nil
}
