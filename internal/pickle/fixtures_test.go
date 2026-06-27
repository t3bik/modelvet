package pickle_test

import (
	"archive/zip"
	"bytes"
)

// pickleBuilder assembles raw pickle opcode bytes for testing.
// No Python or pickle library is used — opcodes are assembled directly.
type pickleBuilder struct {
	buf []byte
}

func newPickle() *pickleBuilder {
	return &pickleBuilder{}
}

// proto emits the PROTO opcode with a version byte.
func (p *pickleBuilder) proto(v byte) *pickleBuilder {
	p.buf = append(p.buf, 0x80, v)
	return p
}

// stop emits the STOP opcode.
func (p *pickleBuilder) stop() *pickleBuilder {
	p.buf = append(p.buf, '.')
	return p
}

// global emits the GLOBAL opcode followed by two newline-terminated lines.
func (p *pickleBuilder) global(module, name string) *pickleBuilder {
	p.buf = append(p.buf, 'c')
	p.buf = append(p.buf, []byte(module+"\n")...)
	p.buf = append(p.buf, []byte(name+"\n")...)
	return p
}

// reduce emits the REDUCE opcode.
func (p *pickleBuilder) reduce() *pickleBuilder {
	p.buf = append(p.buf, 'R')
	return p
}

// mark emits the MARK opcode.
func (p *pickleBuilder) mark() *pickleBuilder {
	p.buf = append(p.buf, '(')
	return p
}

// binstring emits a SHORT_BINSTRING with the given value.
func (p *pickleBuilder) binstring(s string) *pickleBuilder {
	p.buf = append(p.buf, 'U', byte(len(s)))
	p.buf = append(p.buf, []byte(s)...)
	return p
}

// build returns the assembled bytes.
func (p *pickleBuilder) build() []byte {
	return p.buf
}

// benignPickle returns a minimal valid pickle: PROTO 2, STOP.
func benignPickle() []byte {
	return newPickle().proto(2).stop().build()
}

// osSystemGadget returns a pickle that calls os.system("id") via REDUCE.
// Assembled entirely from opcode bytes — no Python pickler involved.
func osSystemGadget() []byte {
	return newPickle().
		proto(2).
		global("os", "system").
		mark().
		binstring("id").
		reduce().
		stop().
		build()
}

// watchListGlobal returns a pickle referencing a watch-list module.
func watchListGlobal() []byte {
	return newPickle().proto(2).global("shutil", "rmtree").stop().build()
}

// truncatedPickle returns a pickle stream without a STOP opcode.
func truncatedPickle() []byte {
	return newPickle().proto(2).global("os", "system").build()
	// no stop()
}

// unknownOpcodePickle returns a pickle with an unrecognised opcode byte.
func unknownOpcodePickle() []byte {
	// 0xFF is not in opcodeTable.
	return []byte{0x80, 0x02, 0xFF}
}

// zipOf wraps a pickle bytes in a PyTorch-style zip container (archive/data.pkl).
func zipOf(pkl []byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("archive/data.pkl")
	if err != nil {
		panic(err)
	}
	if _, err := w.Write(pkl); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// zipWithManyEntries creates a zip with n fake entries (to trigger PKL-ZIP-001).
func zipWithManyEntries(n int) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < n; i++ {
		w, _ := zw.Create("entry_" + string(rune('0'+i%10)) + ".bin")
		_, _ = w.Write([]byte("x"))
	}
	_ = zw.Close()
	return buf.Bytes()
}
