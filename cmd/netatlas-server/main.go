// Command netatlas-server — точка входа сервера NetAtlas.
package main

import (
	"fmt"

	"github.com/ShkodnikAI/NetAtlas/internal/version"
)

func main() {
	fmt.Println(version.String())
}
