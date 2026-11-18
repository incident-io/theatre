package pamrolebinding

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var invalidNameChars = regexp.MustCompile(`[^a-z0-9-]+`)

// RoleBindingName is pam-<binding>-<local part of the email>-<hash>. The hash covers the
// binding's name and the grant's, so each grant gets its own name, which no other binding
// or grant can collide with even where their names run together.
func RoleBindingName(bindingName, user, grant string) string {
	sum := sha256.Sum256([]byte(bindingName + "\x00" + grant))
	suffix := "-" + hex.EncodeToString(sum[:])[:8]

	name := "pam-" + bindingName + "-" + localPart(user)
	// Kubernetes allows 253 characters. Truncate the readable part, never the hash.
	const maxLen = 253
	if len(name)+len(suffix) > maxLen {
		name = strings.TrimRight(name[:maxLen-len(suffix)], "-")
	}
	return name + suffix
}

func localPart(email string) string {
	local, _, _ := strings.Cut(strings.ToLower(email), "@")
	local = strings.Trim(invalidNameChars.ReplaceAllString(local, "-"), "-")
	if local == "" {
		local = "user"
	}
	return local
}
