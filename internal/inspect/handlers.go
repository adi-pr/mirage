package inspect

import (
	"fmt"
	"net/http"
)

// handleHealthz reports that the process is up. It returns 200 with "ok".
func handleHealthz(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "ok")
}
