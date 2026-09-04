package coordinator

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var npyShapePattern = regexp.MustCompile(`['\"]shape['\"]\s*:\s*\((\d+)\s*,\s*\)`)

func decodeNPYFloat32(payload []byte) ([]float32, error) {
	if len(payload) < 10 || !bytes.Equal(payload[:6], []byte("\x93NUMPY")) {
		return nil, errors.New("payload is not a NumPy .npy file")
	}

	major := payload[6]
	var headerLength int
	var headerOffset int
	switch major {
	case 1:
		if len(payload) < 10 {
			return nil, errors.New("truncated NumPy v1 header")
		}
		headerLength = int(binary.LittleEndian.Uint16(payload[8:10]))
		headerOffset = 10
	case 2, 3:
		if len(payload) < 12 {
			return nil, errors.New("truncated NumPy v2/v3 header")
		}
		headerLength = int(binary.LittleEndian.Uint32(payload[8:12]))
		headerOffset = 12
	default:
		return nil, fmt.Errorf("unsupported NumPy format version %d", major)
	}

	if headerLength <= 0 || headerOffset+headerLength > len(payload) {
		return nil, errors.New("invalid NumPy header length")
	}
	header := string(payload[headerOffset : headerOffset+headerLength])
	if !strings.Contains(header, "'descr': '<f4'") &&
		!strings.Contains(header, "\"descr\": \"<f4\"") &&
		!strings.Contains(header, "'descr': '|f4'") &&
		!strings.Contains(header, "\"descr\": \"|f4\"") {
		return nil, errors.New("model vector must use little-endian float32 dtype")
	}
	if strings.Contains(header, "'fortran_order': True") || strings.Contains(header, "\"fortran_order\": True") {
		return nil, errors.New("Fortran-ordered model arrays are not supported")
	}

	match := npyShapePattern.FindStringSubmatch(header)
	if len(match) != 2 {
		return nil, errors.New("model payload must be a one-dimensional NumPy array")
	}
	count, err := strconv.Atoi(match[1])
	if err != nil || count <= 0 {
		return nil, errors.New("model payload has an invalid vector length")
	}

	body := payload[headerOffset+headerLength:]
	if len(body) != count*4 {
		return nil, errors.New("NumPy payload length does not match declared vector shape")
	}

	values := make([]float32, count)
	for i := range values {
		bits := binary.LittleEndian.Uint32(body[i*4 : i*4+4])
		value := math.Float32frombits(bits)
		if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
			return nil, errors.New("model vector contains non-finite values")
		}
		values[i] = value
	}
	return values, nil
}

func encodeNPYFloat32(values []float32) ([]byte, error) {
	if len(values) == 0 {
		return nil, errors.New("cannot encode an empty model vector")
	}
	for _, value := range values {
		if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
			return nil, errors.New("cannot encode non-finite model values")
		}
	}

	header := fmt.Sprintf("{'descr': '<f4', 'fortran_order': False, 'shape': (%d,), }", len(values))
	padding := 16 - ((10 + len(header) + 1) % 16)
	if padding == 16 {
		padding = 0
	}
	header += strings.Repeat(" ", padding) + "\n"
	if len(header) > math.MaxUint16 {
		return nil, errors.New("NumPy header is too large")
	}

	payload := make([]byte, 10+len(header)+len(values)*4)
	copy(payload[:6], []byte("\x93NUMPY"))
	payload[6] = 1
	payload[7] = 0
	binary.LittleEndian.PutUint16(payload[8:10], uint16(len(header)))
	copy(payload[10:10+len(header)], []byte(header))
	body := payload[10+len(header):]
	for i, value := range values {
		binary.LittleEndian.PutUint32(body[i*4:i*4+4], math.Float32bits(value))
	}
	return payload, nil
}
