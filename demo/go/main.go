// 审计引擎验收用的靶子：故意保留漏洞，不要在生产使用。
// FIXTURE ONLY - intentionally vulnerable.
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func Search(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	q := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
	db.Query(q)
}

func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	exec.Command("ping", "-c", "1", host)
}

func Fetch(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	http.Get(url)
}
