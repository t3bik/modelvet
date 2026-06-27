package gguf

// ggml KV metadata value-type enum (ggml_metadata_value_type).
// Valid codes are 0–12; anything else triggers GGUF-KV-TYPE-001.
// Source: llama.cpp gguf.h (as of 2024-Q4).
func validKVType(code uint32) bool {
	return code <= 12
}

// ggml tensor type enum (ggml_type).
// Known codes 0–33; anything else triggers GGUF-TTYPE-001.
// Source: llama.cpp ggml.h (as of 2024-Q4).
var knownGGMLTypes = map[uint32]bool{
	0: true, // GGML_TYPE_F32
	1: true, // GGML_TYPE_F16
	2: true, // GGML_TYPE_Q4_0
	3: true, // GGML_TYPE_Q4_1
	6: true, // GGML_TYPE_Q5_0
	7: true, // GGML_TYPE_Q5_1
	8: true, // GGML_TYPE_Q8_0
	9: true, // GGML_TYPE_Q8_1
	// k-quants
	10: true, // GGML_TYPE_Q2_K
	11: true, // GGML_TYPE_Q3_K
	12: true, // GGML_TYPE_Q4_K
	13: true, // GGML_TYPE_Q5_K
	14: true, // GGML_TYPE_Q6_K
	15: true, // GGML_TYPE_Q8_K
	16: true, // GGML_TYPE_IQ2_XXS
	17: true, // GGML_TYPE_IQ2_XS
	18: true, // GGML_TYPE_IQ3_XXS
	19: true, // GGML_TYPE_IQ1_S
	20: true, // GGML_TYPE_IQ4_NL
	21: true, // GGML_TYPE_IQ3_S
	22: true, // GGML_TYPE_IQ2_S
	23: true, // GGML_TYPE_IQ4_XS
	24: true, // GGML_TYPE_I8
	25: true, // GGML_TYPE_I16
	26: true, // GGML_TYPE_I32
	27: true, // GGML_TYPE_I64
	28: true, // GGML_TYPE_F64
	29: true, // GGML_TYPE_IQ1_M
	30: true, // GGML_TYPE_BF16
	31: true, // GGML_TYPE_Q4_0_4_4
	32: true, // GGML_TYPE_Q4_0_4_8
	33: true, // GGML_TYPE_Q4_0_8_8
}

func validGGMLType(code uint32) bool {
	return knownGGMLTypes[code]
}

// ggmlTypeBlockBytes returns the number of bytes per block for a given ggml type,
// used to compute tensor byte sizes. Returns (bytes_per_block, elements_per_block).
// For unquantized types, elements_per_block == 1.
// Returns (0, 0) for unknown types.
func ggmlTypeBlockBytes(ttype uint32) (bytesPerBlock uint64, elemsPerBlock uint64) {
	switch ttype {
	case 0: // F32
		return 4, 1
	case 1: // F16
		return 2, 1
	case 2: // Q4_0: 18 bytes / 32 elems
		return 18, 32
	case 3: // Q4_1: 20 bytes / 32 elems
		return 20, 32
	case 6: // Q5_0: 22 bytes / 32 elems
		return 22, 32
	case 7: // Q5_1: 24 bytes / 32 elems
		return 24, 32
	case 8: // Q8_0: 34 bytes / 32 elems
		return 34, 32
	case 9: // Q8_1: 36 bytes / 32 elems
		return 36, 32
	case 10: // Q2_K: 256 bytes / 256 elems
		return 256, 256
	case 11: // Q3_K: 110 bytes / 256 elems
		return 110, 256
	case 12: // Q4_K: 144 bytes / 256 elems
		return 144, 256
	case 13: // Q5_K: 176 bytes / 256 elems
		return 176, 256
	case 14: // Q6_K: 210 bytes / 256 elems
		return 210, 256
	case 15: // Q8_K: 292 bytes / 256 elems
		return 292, 256
	case 24: // I8
		return 1, 1
	case 25: // I16
		return 2, 1
	case 26: // I32
		return 4, 1
	case 27: // I64
		return 8, 1
	case 28: // F64
		return 8, 1
	case 30: // BF16
		return 2, 1
	default:
		// For unknown or recently added types, we cannot compute size.
		return 0, 0
	}
}
