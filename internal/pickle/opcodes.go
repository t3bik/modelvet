package pickle

// argKind describes how to parse the argument that follows an opcode byte.
type argKind int

const (
	argNone      argKind = iota // no argument
	argByte                     // 1-byte inline argument
	argShort                    // 2-byte LE argument
	argInt4                     // 4-byte LE argument
	argInt8                     // 8-byte LE argument
	argLine                     // newline-terminated ASCII string
	argLine2                    // two newline-terminated lines (GLOBAL: module \n name \n)
	argDecimal                  // newline-terminated decimal integer
	argBytes1                   // 1-byte length prefix then that many bytes
	argBytes4                   // 4-byte LE length prefix then that many bytes
	argBytes8                   // 8-byte LE length prefix then that many bytes
	argUnicode                  // newline-terminated unicode escaped string
	argUnicode4                 // 4-byte LE length then UTF-8 bytes
	argInst                     // two newline-terminated lines (module \n name), like GLOBAL
)

// opInfo describes one pickle opcode.
type opInfo struct {
	name string
	arg  argKind
}

// opcodeTable maps opcode byte to opInfo.
// Covers pickle protocols 0–5. Unknown bytes are not in the table.
var opcodeTable = map[byte]opInfo{
	// Protocol 0 (text-based)
	'(':  {"MARK", argNone},
	'.':  {"STOP", argNone},
	'0':  {"POP", argNone},
	'1':  {"POP_MARK", argNone},
	'2':  {"DUP", argNone},
	'F':  {"FLOAT", argLine},
	'I':  {"INT", argLine},
	'J':  {"LONG", argLine},
	'K':  {"BININT1", argByte},
	'L':  {"LONG_PLAIN", argLine}, // protocol 0 LONG (terminated by 'L\n')
	'M':  {"BININT2", argShort},
	'N':  {"NONE", argNone},
	'S':  {"STRING", argLine},
	'T':  {"BINSTRING", argBytes4},
	'U':  {"SHORT_BINSTRING", argBytes1},
	'V':  {"UNICODE", argUnicode},
	'X':  {"BINUNICODE", argUnicode4},
	'a':  {"APPEND", argNone},
	'b':  {"BUILD", argNone},
	'c':  {"GLOBAL", argLine2},
	'd':  {"DICT", argNone},
	'e':  {"APPENDS", argNone},
	'g':  {"GET", argLine},
	'h':  {"BINGET", argByte},
	'i':  {"INST", argInst},
	'j':  {"LONG_BINGET", argInt4},
	'l':  {"LIST", argNone},
	'o':  {"OBJ", argNone},
	'p':  {"PUT", argLine},
	'q':  {"BINPUT", argByte},
	'r':  {"LONG_BINPUT", argInt4},
	's':  {"SETITEM", argNone},
	't':  {"TUPLE", argNone},
	'u':  {"SETITEMS", argNone},
	'}':  {"EMPTY_DICT", argNone},
	')':  {"EMPTY_TUPLE", argNone},
	']':  {"EMPTY_LIST", argNone},

	// Protocol 2
	0x80: {"PROTO", argByte},
	0x81: {"NEWOBJ", argNone},
	0x82: {"EXT1", argByte},
	0x83: {"EXT2", argShort},
	0x84: {"EXT4", argInt4},
	0x85: {"TUPLE1", argNone},
	0x86: {"TUPLE2", argNone},
	0x87: {"TUPLE3", argNone},
	0x88: {"NEWTRUE", argNone},
	0x89: {"NEWFALSE", argNone},
	0x8a: {"LONG1", argBytes1},
	0x8b: {"LONG4", argBytes4},

	// Protocol 3
	'B':  {"BINBYTES", argBytes4},
	'C':  {"SHORT_BINBYTES", argBytes1},

	// Protocol 4
	0x8c: {"SHORT_BINUNICODE", argBytes1},
	0x8d: {"BINUNICODE8", argBytes8},
	0x8e: {"BINBYTES8", argBytes8},
	0x8f: {"EMPTY_SET", argNone},
	0x90: {"ADDITEMS", argNone},
	0x91: {"FROZENSET", argNone},
	0x92: {"NEWOBJ_EX", argNone},
	0x93: {"STACK_GLOBAL", argNone}, // module/name come from stack
	0x94: {"MEMOIZE", argNone},
	0x95: {"FRAME", argInt8},

	// Protocol 5
	0x96: {"BYTEARRAY8", argBytes8},
	0x97: {"NEXT_BUFFER", argNone},
	0x98: {"READONLY_BUFFER", argNone},

	// Legacy
	'R':  {"REDUCE", argNone},
	'G':  {"BINFLOAT", argInt8}, // 8-byte BE float (same wire size as int8)
	'H':  {"BININT", argInt4},
}
