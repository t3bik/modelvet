package pickle

// denyModules maps module names that are known code-execution vectors.
// A GLOBAL/STACK_GLOBAL referencing one of these → PKL-GLOBAL-001 (Critical).
// Keeping this as a reviewable table (not buried regexes) is deliberate.
var denyModules = map[string]bool{
	"os":          true,
	"posix":       true,
	"nt":          true,
	"subprocess":  true,
	"sys":         true,
	"runpy":       true,
	"builtins":    true,
	"__builtin__": true,
	"importlib":   true,
	"pty":         true,
	"socket":      true,
	"ctypes":      true,
	"cffi":        true,
	"_posixsubprocess": true,
}

// watchModules maps capability-enabling modules that warrant human review.
// A GLOBAL/STACK_GLOBAL referencing one of these → PKL-GLOBAL-002 (High).
var watchModules = map[string]bool{
	"shutil":      true,
	"pickle":      true,
	"webbrowser":  true,
	"base64":      true,
	"codecs":      true,
	"operator":    true,
	"functools":   true,
	"itertools":   true,
	"marshal":     true,
	"io":          true,
	"tempfile":    true,
	"glob":        true,
	"fnmatch":     true,
}

// isDeny reports whether the module is in the deny list.
func isDeny(module string) bool { return denyModules[module] }

// isWatch reports whether the module is in the watch list.
func isWatch(module string) bool { return watchModules[module] }
