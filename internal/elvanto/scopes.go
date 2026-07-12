package elvanto

import (
	"fmt"
)

func FacadeScopes() []string {
	return []string{
		"openid",
		"email",
		"profile",
	}
}

func SupportedScopes() []string {
	return []string{
		"ManagePeople",
		"ManageGroups",
		"ManageServices",
		"ManageSongs",
		"ManageCalendar",
		"ManageFinancials",
		"AdministerAccount",
	}
}

func ValidateScopes(scopes []string) ([]string, error) {
	results := []string{}

	allowed := make(map[string]bool)
	for _, value := range SupportedScopes() {
		allowed[value] = true
	}
	skip := make(map[string]bool)
	for _, value := range FacadeScopes() {
		skip[value] = true
	}

	for _, value := range scopes {
		if skip[value] {
			continue
		}
		if !allowed[value] {
			return results, fmt.Errorf("unsupported scope %q", value)
		}
		results = append(results, value)
	}

	return results, nil
}
