package commands

import "strings"

func CalculateDisallowedMechanisms(allMechanisms, allowedMechanisms []string) []string {
	disallowed := make([]string, 0, len(allMechanisms))

	for _, mechanism := range allMechanisms {
		found := false

		for _, allowed := range allowedMechanisms {
			if strings.EqualFold(mechanism, allowed) {
				found = true

				break
			}
		}

		if !found {
			disallowed = append(disallowed, mechanism)
		}
	}

	return disallowed
}
