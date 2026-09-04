package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// VerifyAuditRecords verifies a complete audit chain beginning at sequence 1.
func VerifyAuditRecords(records []AuditRecord) error {
	return verifyAuditRecords(records, nil, 0)
}

// DecodeAuditNDJSON strictly decodes and verifies a complete bounded audit
// export. JSON objects may be separated only by JSON whitespace, which includes
// the newline-delimited format produced by ExportAuditNDJSON.
func DecodeAuditNDJSON(reader io.Reader, limit int) ([]AuditRecord, error) {
	if reader == nil {
		return nil, errors.New("audit NDJSON reader is required")
	}
	if limit <= 0 {
		limit = maxAuditExportRows
	}
	if limit > maxAuditExportRows {
		return nil, fmt.Errorf("audit NDJSON limit exceeds %d rows", maxAuditExportRows)
	}

	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	records := make([]AuditRecord, 0)
	for {
		var record AuditRecord
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode audit NDJSON record %d: %w", len(records)+1, err)
		}
		if len(records) >= limit {
			return nil, fmt.Errorf("audit NDJSON contains more than %d records", limit)
		}
		records = append(records, record)
	}
	if err := VerifyAuditRecords(records); err != nil {
		return nil, fmt.Errorf("verify audit NDJSON chain: %w", err)
	}
	return records, nil
}
