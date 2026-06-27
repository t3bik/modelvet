package safetensors_test

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// stBuilder assembles raw safetensors bytes for testing without any binary files.
type stBuilder struct {
	tensors  map[string]stTensor
	metadata map[string]string
}

type stTensor struct {
	Dtype       string  `json:"dtype"`
	Shape       []int64 `json:"shape"`
	DataOffsets [2]int64 `json:"data_offsets"`
}

func newST() *stBuilder {
	return &stBuilder{
		tensors: make(map[string]stTensor),
	}
}

// addTensor adds a tensor with valid offsets pointing into a data segment.
func (b *stBuilder) addTensor(name, dtype string, shape []int64, begin, end int64) *stBuilder {
	b.tensors[name] = stTensor{Dtype: dtype, Shape: shape, DataOffsets: [2]int64{begin, end}}
	return b
}

// withMetadata sets a metadata key-value pair.
func (b *stBuilder) withMetadata(k, v string) *stBuilder {
	if b.metadata == nil {
		b.metadata = make(map[string]string)
	}
	b.metadata[k] = v
	return b
}

// build creates a minimal valid safetensors file with a data segment of dataSize bytes.
func (b *stBuilder) build(dataSize int64) []byte {
	hdr := make(map[string]interface{})
	for name, t := range b.tensors {
		hdr[name] = t
	}
	if b.metadata != nil {
		hdr["__metadata__"] = b.metadata
	}
	headerBytes, err := json.Marshal(hdr)
	if err != nil {
		panic(fmt.Sprintf("stBuilder.build: marshal: %v", err))
	}
	var buf []byte
	buf = appendU64(buf, uint64(len(headerBytes)))
	buf = append(buf, headerBytes...)
	buf = append(buf, make([]byte, dataSize)...)
	return buf
}

// withHeaderLen returns a safetensors file where the 8-byte length field is
// overwritten with a specific value.
func withHeaderLen(headerLen uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], headerLen)
	return buf[:]
}

// withBadJSON returns a safetensors file with a corrupted JSON header.
func withBadJSON() []byte {
	hdr := []byte("{not valid json")
	var buf []byte
	buf = appendU64(buf, uint64(len(hdr)))
	buf = append(buf, hdr...)
	return buf
}

// withOversizedHeaderLen returns bytes claiming a header larger than the file.
func withOversizedHeaderLen(fileSize int64) []byte {
	// header_len = fileSize (which is > fileSize - 8)
	var buf [8 + 10]byte // minimal 10-byte "file"
	binary.LittleEndian.PutUint64(buf[:8], uint64(fileSize+1))
	return buf[:fileSize]
}

// withDoSHeaderLen returns bytes with a header_len > 100 MiB.
func withDoSHeaderLen() []byte {
	const dosLen = 200 << 20 // 200 MiB > headerCap (100 MiB)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], dosLen)
	// Append enough bytes so it doesn't look OOB but stays huge.
	// We keep the actual file tiny; ST-HEADERLEN-002 fires before ST-HEADERLEN-001.
	// Actually for ST-HEADERLEN-002, header_len must be <= size-8 first, so
	// let's craft size = dosLen+8 to pass the OOB check.
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint64(payload[:], dosLen)
	// Return just the 8-byte prefix; the scanner sees header_len > size-8 (ST-HEADERLEN-001).
	// To trigger ST-HEADERLEN-002 we need file >= dosLen+8.
	// For testing purposes this triggers ST-HEADERLEN-001 (which is fine for the test).
	return payload
}

// withDoSHeaderLenLarge returns a file big enough that ST-HEADERLEN-002 fires.
// The file is ~100 MiB + 9 bytes: the minimum size for header_len > headerCap
// (100 MiB + 1) while satisfying header_len <= size - 8.
// This is used in unit tests only — do NOT add this as a fuzz seed because it
// exceeds the Go fuzzer 100 MiB shared-memory cap.
func withDoSHeaderLenLarge() []byte {
	// headerCap = 100 MiB; claim exactly 1 byte over the cap.
	const testDoSLen = uint64(100<<20) + 1
	// File must be >= testDoSLen + 8 so ST-HEADERLEN-001 does not fire first.
	buf := make([]byte, testDoSLen+8+1)
	binary.LittleEndian.PutUint64(buf[:8], testDoSLen)
	buf[8] = '{' // minimal JSON-start hint (not strictly required)
	return buf
}

// withDoSHeaderLenFuzzSeed returns a small byte sequence exercising the
// large-header-len code path, designed to stay within the Go fuzzer 100 MiB
// shared-memory cap. It triggers ST-HEADERLEN-001 (header_len > size-8).
func withDoSHeaderLenFuzzSeed() []byte {
	const testDoSLen = uint64(100<<20) + 1
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], testDoSLen)
	return buf[:]
}

// appendU64 appends a LE uint64.
func appendU64(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}
