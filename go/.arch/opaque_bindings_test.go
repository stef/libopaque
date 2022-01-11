package opaque_bindings

import (
	"fmt"
	"testing"
)

func test(t *testing.T) {
	fmt.Println(opaque_bindings.greet("Gopher", 2022))
}
