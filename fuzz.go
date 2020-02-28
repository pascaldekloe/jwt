// +build gofuzz

package jwt

// Fuzz implements the github.com/dvyukov/go-fuzz interface.
func Fuzz(data []byte) int {
	_, err := ParseWithoutCheck(data)
	if err != nil {
		return 0
	}
	return 1
}
