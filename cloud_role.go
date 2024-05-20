package saml2aws

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/versent/saml2aws/v2/pkg/cloud"
)

// CloudRole aws role attributes
type CloudRole struct {
	Provider     cloud.Provider
	RoleARN      string
	PrincipalARN string
	Name         string
}

// ParseCloudRoles parses and splits the roles while also validating the contents
func ParseCloudRoles(roles []string, cp cloud.Provider) ([]*CloudRole, error) {
	awsRoles := make([]*CloudRole, len(roles))

	for i, role := range roles {
		awsRole, err := parseRole(role, cp)
		if err != nil {
			return nil, err
		}

		awsRoles[i] = awsRole
	}

	return awsRoles, nil
}

func parseRole(role string, cp cloud.Provider) (*CloudRole, error) {
	var r *regexp.Regexp
	switch cp {
	case cloud.AWS:
		r, _ = regexp.Compile("arn:([^:\n]*):([^:\n]*):([^:\n]*):([^:\n]*):(([^:/\n]*)[:/])?([^:,\n]*)")
	case cloud.TencentCloud:
		r, _ = regexp.Compile("qcs::([^:]*):([^:]*):([^:]*):([^:/]*)(/[^,]*)?")

	default:
		return nil, fmt.Errorf("Invalid provider:")
	}

	// log.Println("Parsing role: ", role)

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
	providerRole.Provider = cp

	if providerRole.PrincipalARN == "" {
		return nil, fmt.Errorf("Unable to locate PrincipalARN in: %s", role)
	}

	if providerRole.RoleARN == "" {
		return nil, fmt.Errorf("Unable to locate RoleARN in: %s", role)
	}

	return providerRole, nil
}
