package generators

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// ID returns a deterministic ID that is  a function of the localID and
// publicKeys
func ID(localID string, publicKeys []string) string {
	toHash := fmt.Sprintf("%v:%v", localID, strings.Join(publicKeys, ","))
	hash := sha256.Sum256([]byte(toHash))

	part1 := hash[0:4]
	part2 := hash[4:6]
	part3 := hash[6:8]
	part4 := hash[8:10]
	part5 := hash[10:16]

	return fmt.Sprintf("%x-%x-%x-%x-%x", part1, part2, part3, part4, part5)
}
