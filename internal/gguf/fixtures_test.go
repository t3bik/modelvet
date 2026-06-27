package gguf_test

import (
	"encoding/binary"
)

// ggufBuilder assembles raw GGUF bytes for testing without any binary files on disk.
type ggufBuilder struct {
	version uint32
	kvs     []ggufKV
	tensors []ggufTensor
}

type ggufKV struct {
	key     string
	kvType  uint32
	val     []byte // raw value bytes (after the type field)
}

type ggufTensor struct {
	name  string
	dims  []uint64
	ttype uint32
	off   uint64
}

func newGGUF() *ggufBuilder {
	return &ggufBuilder{version: 3}
}

func (b *ggufBuilder) kv(key string, kvType uint32, rawVal []byte) *ggufBuilder {
	b.kvs = append(b.kvs, ggufKV{key: key, kvType: kvType, val: rawVal})
	return b
}

func (b *ggufBuilder) tensor(name string, dims []uint64, ttype uint32, off uint64) *ggufBuilder {
	b.tensors = append(b.tensors, ggufTensor{name: name, dims: dims, ttype: ttype, off: off})
	return b
}

// build assembles a well-formed GGUF byte slice.
func (b *ggufBuilder) build() []byte {
	var buf []byte

	// magic
	buf = append(buf, []byte("GGUF")...)
	// version
	buf = appendU32(buf, b.version)
	// tensor_count
	buf = appendU64(buf, uint64(len(b.tensors)))
	// metadata_kv_count
	buf = appendU64(buf, uint64(len(b.kvs)))

	// KV entries
	for _, kv := range b.kvs {
		buf = appendStr(buf, kv.key)
		buf = appendU32(buf, kv.kvType)
		buf = append(buf, kv.val...)
	}

	// Tensor info entries
	for _, t := range b.tensors {
		buf = appendStr(buf, t.name)
		buf = appendU32(buf, uint32(len(t.dims)))
		for _, d := range t.dims {
			buf = appendU64(buf, d)
		}
		buf = appendU32(buf, t.ttype)
		buf = appendU64(buf, t.off)
	}

	return buf
}

// withBadMagic returns bytes with corrupted magic.
func (b *ggufBuilder) withBadMagic() []byte {
	raw := b.build()
	raw[0] = 'X'
	return raw
}

// withKVType returns bytes where the first KV entry has a forced type code.
func (b *ggufBuilder) withKVType(code uint32) []byte {
	// Build a GGUF with one KV entry; override its type byte.
	g := &ggufBuilder{version: b.version}
	g.kvs = []ggufKV{{key: "foo", kvType: code, val: []byte{0x01}}} // 1-byte placeholder val
	return g.build()
}

// withHugeKVCount returns bytes with an absurd metadata_kv_count.
func (b *ggufBuilder) withHugeKVCount(n uint64) []byte {
	raw := b.build()
	binary.LittleEndian.PutUint64(raw[16:24], n)
	return raw
}

// withHugeTensorCount returns bytes with an absurd tensor_count.
func (b *ggufBuilder) withHugeTensorCount(n uint64) []byte {
	raw := b.build()
	binary.LittleEndian.PutUint64(raw[8:16], n)
	return raw
}

// withVersion returns bytes with a given version field.
func (b *ggufBuilder) withVersion(v uint32) []byte {
	raw := b.build()
	binary.LittleEndian.PutUint32(raw[4:8], v)
	return raw
}

// withNDims returns a GGUF where the first tensor has an absurd n_dims.
// The tensor is otherwise minimal.
func (b *ggufBuilder) withNDims(nDims uint32) []byte {
	var buf []byte
	buf = append(buf, []byte("GGUF")...)
	buf = appendU32(buf, 3) // version
	buf = appendU64(buf, 1) // tensor_count
	buf = appendU64(buf, 0) // kv_count
	// Tensor: name "t"
	buf = appendStr(buf, "t")
	buf = appendU32(buf, nDims) // n_dims — absurd value
	// No dim values follow (we want the parse to fail on n_dims check).
	return buf
}

// withDimOverflow returns a GGUF where the first tensor has dims that overflow uint64.
func (b *ggufBuilder) withDimOverflow() []byte {
	var buf []byte
	buf = append(buf, []byte("GGUF")...)
	buf = appendU32(buf, 3)
	buf = appendU64(buf, 1) // tensor_count
	buf = appendU64(buf, 0) // kv_count
	buf = appendStr(buf, "t")
	buf = appendU32(buf, 2) // n_dims = 2
	buf = appendU64(buf, 1<<32)
	buf = appendU64(buf, 1<<32) // product overflows uint64
	buf = appendU32(buf, 0)     // ggml_type F32
	buf = appendU64(buf, 0)     // offset
	return buf
}

// withOffsetPastEOF returns a GGUF where the first tensor's offset+size > filesize.
func (b *ggufBuilder) withOffsetPastEOF() []byte {
	var buf []byte
	buf = append(buf, []byte("GGUF")...)
	buf = appendU32(buf, 3)
	buf = appendU64(buf, 1) // tensor_count
	buf = appendU64(buf, 0) // kv_count
	buf = appendStr(buf, "t")
	buf = appendU32(buf, 1)    // n_dims = 1
	buf = appendU64(buf, 100)  // 100 elements
	buf = appendU32(buf, 0)    // F32 = 4 bytes/elem → 400 bytes total
	buf = appendU64(buf, 9999) // offset way past end of this tiny file
	return buf
}

// withDupKey returns bytes with duplicate KV keys.
func (b *ggufBuilder) withDupKey() []byte {
	g := &ggufBuilder{version: 3}
	val := make([]byte, 1) // bool value
	g.kvs = []ggufKV{
		{key: "same", kvType: 7, val: val},
		{key: "same", kvType: 7, val: val},
	}
	return g.build()
}

// withHugeString returns a GGUF with a key whose length field claims a string
// larger than the file.
func (b *ggufBuilder) withHugeString() []byte {
	var buf []byte
	buf = append(buf, []byte("GGUF")...)
	buf = appendU32(buf, 3)
	buf = appendU64(buf, 0) // tensor_count
	buf = appendU64(buf, 1) // kv_count
	// KV with key-length way beyond file size
	buf = appendU64(buf, 0xFFFFFFFF) // key length = 4 GiB
	// no actual bytes — file ends here
	return buf
}

// truncatedAt returns the first n bytes (simulating a truncated file).
func (b *ggufBuilder) truncatedAt(n int) []byte {
	raw := b.build()
	if n > len(raw) {
		return raw
	}
	return raw[:n]
}

// ── byte helpers ──────────────────────────────────────────────────────────────

func appendU32(buf []byte, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return append(buf, b[:]...)
}

func appendU64(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}

func appendStr(buf []byte, s string) []byte {
	buf = appendU64(buf, uint64(len(s)))
	return append(buf, []byte(s)...)
}
