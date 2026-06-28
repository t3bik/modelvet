package scan_test

import (
	"bytes"
	"testing"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/scan"
)

func detect(data []byte, name string) scan.DetectedFormat {
	return scan.Detect(bytes.NewReader(data), int64(len(data)), name)
}

func TestDetect_ggufMagic(t *testing.T) {
	data := append([]byte("GGUF"), make([]byte, 20)...)
	d := detect(data, "model.gguf")
	if d.Format != finding.FormatGGUF {
		t.Fatalf("expected GGUF, got %v", d.Format)
	}
	if !d.ByMagic {
		t.Fatal("expected ByMagic=true for GGUF magic")
	}
}

func TestDetect_ggufExtension(t *testing.T) {
	// No GGUF magic (starts with zeros), but has .gguf extension.
	data := make([]byte, 20)
	d := detect(data, "model.gguf")
	if d.Format != finding.FormatGGUF {
		t.Fatalf("expected GGUF, got %v", d.Format)
	}
}

func TestDetect_safetensors(t *testing.T) {
	// 8-byte LE length (any value), then '{'.
	data := make([]byte, 20)
	data[8] = '{'
	d := detect(data, "weights.safetensors")
	if d.Format != finding.FormatSafetensors {
		t.Fatalf("expected safetensors, got %v", d.Format)
	}
}

func TestDetect_safetensorsExtensionOnly(t *testing.T) {
	// byte[8] != '{' but extension is .safetensors.
	data := make([]byte, 20)
	data[8] = 'X'
	d := detect(data, "weights.safetensors")
	if d.Format != finding.FormatSafetensors {
		t.Fatalf("expected safetensors by extension, got %v", d.Format)
	}
}

func TestDetect_pickleZipMagic(t *testing.T) {
	data := []byte{'P', 'K', 0x03, 0x04} // ZIP magic
	data = append(data, make([]byte, 20)...)
	d := detect(data, "model.pt")
	if d.Format != finding.FormatPickle {
		t.Fatalf("expected pickle (zip), got %v", d.Format)
	}
	if !d.ByMagic {
		t.Fatal("expected ByMagic=true for PK magic")
	}
}

func TestDetect_pickleProtoMagic(t *testing.T) {
	data := []byte{0x80, 0x02, '.'} // PROTO 2, STOP
	d := detect(data, "model.pkl")
	if d.Format != finding.FormatPickle {
		t.Fatalf("expected pickle, got %v", d.Format)
	}
}

func TestDetect_pickleExtension(t *testing.T) {
	data := make([]byte, 10)
	d := detect(data, "model.bin")
	if d.Format != finding.FormatPickle {
		t.Fatalf("expected pickle by .bin extension, got %v", d.Format)
	}
}

func TestDetect_unknown(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	d := detect(data, "random.xyz")
	if d.Format != finding.FormatUnknown {
		t.Fatalf("expected unknown, got %v", d.Format)
	}
}

func TestDetect_magicBeatsExtension(t *testing.T) {
	// File has GGUF magic but .pkl extension — magic should win.
	data := append([]byte("GGUF"), make([]byte, 20)...)
	d := detect(data, "model.pkl")
	if d.Format != finding.FormatGGUF {
		t.Fatalf("expected GGUF (magic beats extension), got %v", d.Format)
	}
	if !d.ByMagic {
		t.Fatal("expected ByMagic=true")
	}
}

func TestDetect_npyMagic(t *testing.T) {
	// \x93NUMPY magic bytes → FormatNumpy, ByMagic=true, regardless of extension.
	data := []byte{0x93, 'N', 'U', 'M', 'P', 'Y', 1, 0, 0, 0, 0, 0}
	d := detect(data, "weights.bin") // wrong extension — magic wins
	if d.Format != finding.FormatNumpy {
		t.Fatalf("expected FormatNumpy by magic, got %v", d.Format)
	}
	if !d.ByMagic {
		t.Fatal("expected ByMagic=true for .npy magic")
	}
}

func TestDetect_npyExtension(t *testing.T) {
	// .npy extension without magic (zeros) → FormatNumpy by extension.
	data := make([]byte, 20)
	d := detect(data, "array.npy")
	if d.Format != finding.FormatNumpy {
		t.Fatalf("expected FormatNumpy by .npy extension, got %v", d.Format)
	}
}

func TestDetect_npzExtensionPKMagic(t *testing.T) {
	// .npz with PK magic → FormatNumpy (not FormatPickle), ByMagic=true.
	data := []byte{'P', 'K', 0x03, 0x04}
	data = append(data, make([]byte, 20)...)
	d := detect(data, "archive.npz")
	if d.Format != finding.FormatNumpy {
		t.Fatalf("expected FormatNumpy for .npz, got %v (should NOT route to pickle)", d.Format)
	}
	if !d.ByMagic {
		t.Fatal("expected ByMagic=true (PK magic confirmed)")
	}
}

func TestDetect_npzExtensionNoPKMagic(t *testing.T) {
	// .npz extension but no PK magic → still FormatNumpy (extension only).
	data := make([]byte, 20)
	d := detect(data, "archive.npz")
	if d.Format != finding.FormatNumpy {
		t.Fatalf("expected FormatNumpy for .npz extension, got %v", d.Format)
	}
}
