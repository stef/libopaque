package opaque_bindings

// #cgo CFLAGS: -g -Wall
// #include <stdlib.h>
// #include "opaque_bindings.h"
import "C"
import (
	"fmt"
	"unsafe"
)

func greet(_name string, _year int) {
	name := C.CString(_name)
	defer C.free(unsafe.Pointer(name))

	year := C.int(_year)

	ptr := C.malloc(C.sizeof_char * 1024)
	defer C.free(unsafe.Pointer(ptr))

	size := C.greet(name, year, (*C.char)(ptr))

	b := C.GoBytes(ptr, size)
	return (string(b))
}
