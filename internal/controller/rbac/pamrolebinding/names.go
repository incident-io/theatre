package pamrolebinding

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var invalidNameChars = regexp.MustCompile(`[^a-z0-9-]+`)

// roleBindingNames picks a RoleBinding name for each user: pam-<binding>-<local part of
// their email>, so `kubectl get rolebindings` shows whose each one is. Users whose local
// parts clash, e.g. the same name at two domains, get a short hash of their email too.
func roleBindingNames(bindingName string, users []string) map[string]string {
	byName := map[string][]string{}
	for _, user := range users {
		name := "pam-" + bindingName + "-" + localPart(user)
		byName[name] = append(byName[name], user)
	}

	names := map[string]string{}
	for name, clashing := range byName {
		for _, user := range clashing {
			if len(clashing) == 1 {
				names[user] = truncate(name, "")
				continue
			}
			sum := sha256.Sum256([]byte(user))
			names[user] = truncate(name, "-"+hex.EncodeToString(sum[:])[:8])
		}
	}

	return names
}

func localPart(email string) string {
	local, _, _ := strings.Cut(strings.ToLower(email), "@")
	local = strings.Trim(invalidNameChars.ReplaceAllString(local, "-"), "-")
	if local == "" {
		local = "user"
	}
	return local
}

// truncate keeps names within the 253 characters Kubernetes allows, with the suffix intact.
func truncate(name, suffix string) string {
	const maxLen = 253
	if len(name)+len(suffix) > maxLen {
		name = strings.TrimRight(name[:maxLen-len(suffix)], "-")
	}
	return name + suffix
}
