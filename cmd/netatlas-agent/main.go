// Command netatlas-agent — точка входа агента NetAtlas.
package main

import (
	"fmt"

	"github.com/ShkodnikAI/NetAtlas/internal/version"
)

func main() {
	fmt.Println(version.String())
}
