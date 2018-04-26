package jwt_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/pascaldekloe/jwt"
)

func ExampleHandler_direct() {
	h := &jwt.Handler{
		Target: nil,
		Secret: []byte("killarcherdie"),

		// use as http.HandlerFunc with JWT argument
		Func: func(w http.ResponseWriter, req *http.Request, claims *jwt.Claims) (pass bool) {
			if n, ok := claims.Number("deadline"); !ok {
				fmt.Fprintln(w, "you don't have a deadline")
			} else {
				t := jwt.NumericTime(n)
				fmt.Fprintln(w, "deadline at", t.String())
			}
			return // false stops processing
		},
	}

	req := httptest.NewRequest("GET", "/status", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJkZWFkbGluZSI6NjcxNTAwNzk5fQ.yeUUNOj4-RvNp5Lt0d3lpS7MTgsS_Uk9XnsXJ3kVLhw")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	fmt.Printf("HTTP %d: %s", resp.Code, resp.Body)
	// output: HTTP 200: deadline at 1991-04-12T23:59:59Z
}
