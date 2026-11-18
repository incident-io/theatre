package pamrolebinding

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var invalidNameChars = regexp.MustCompile(`[^a-z0-9-]+`)

// RoleBindingName is pam-<binding>-<local part of the email>-<hash>. The hash covers the
// binding's name and the full email, so a name depends on nothing else, and two users or
// bindings can't collide even where their names run together.
func RoleBindingName(bindingName, user string) string {
	sum := sha256.Sum256([]byte(bindingName + "\x00" + user))
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
