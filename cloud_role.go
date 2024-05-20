package saml2aws

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// CloudRole aws role attributes
type CloudRole struct {
	Provider     string
	RoleARN      string
	PrincipalARN string
	Name         string
}

// ParseCloudRoles parses and splits the roles while also validating the contents
func ParseCloudRoles(roles []string, provider string) ([]*CloudRole, error) {
	awsRoles := make([]*CloudRole, len(roles))

	for i, role := range roles {
		awsRole, err := parseRole(role, provider)
		if err != nil {
			return nil, err
		}

		awsRoles[i] = awsRole
	}

	return awsRoles, nil
}

func parseRole(role, provider string) (*CloudRole, error) {
	var r *regexp.Regexp
	switch provider {
	case "AWS":
		r, _ = regexp.Compile("arn:([^:\n]*):([^:\n]*):([^:\n]*):([^:\n]*):(([^:/\n]*)[:/])?([^:,\n]*)")
	case "TencentCloud":
		r, _ = regexp.Compile("qcs::([^:\\n]*):([^:\\n]*):([^:\\n]*):([^:/\\n]*)([/]([^,]*)|:([^,\\n]*))\n")
	default:
		return nil, fmt.Errorf("Invalid provider: %s", provider)
	}

	log.Println("Parsing role: ", role)
	tokens := r.FindAllString(role, -1)
	if len(tokens) != 2 {
		return nil, fmt.Errorf("Invalid role string only %d tokens", len(tokens))
	}

	providerRole := &CloudRole{}
	for _, token := range tokens {
		if strings.Contains(token, ":saml-provider") {
			providerRole.PrincipalARN = strings.TrimSpace(token)
		}
		if strings.Contains(token, ":role") {
			providerRole.RoleARN = strings.TrimSpace(token)
		}
	}
	providerRole.Provider = provider

	if providerRole.PrincipalARN == "" {
		return nil, fmt.Errorf("Unable to locate PrincipalARN in: %s", role)
	}

	if providerRole.RoleARN == "" {
		return nil, fmt.Errorf("Unable to locate RoleARN in: %s", role)
	}

	return providerRole, nil
}
