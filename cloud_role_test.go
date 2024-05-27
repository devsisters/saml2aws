package saml2aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRoles(t *testing.T) {

	roles := []string{
		"arn:aws:iam::456456456456:saml-provider/example-idp,arn:aws:iam::456456456456:role/admin",
		"arn:aws:iam::456456456456:role/admin,arn:aws:iam::456456456456:saml-provider/example-idp",
	}

	awsRoles, err := ParseCloudRoles(roles, "AWS")

	assert.Nil(t, err)
	assert.Len(t, awsRoles, 2)

	for _, awsRole := range awsRoles {
		assert.Equal(t, "arn:aws:iam::456456456456:saml-provider/example-idp", awsRole.PrincipalARN)
		assert.Equal(t, "arn:aws:iam::456456456456:role/admin", awsRole.RoleARN)
	}

	roles = []string{""}
	awsRoles, err = ParseCloudRoles(roles, "AWS")

	assert.NotNil(t, err)
	assert.Nil(t, awsRoles)

	// TencentCloud Roles
	roles = []string{
		"qcs::cam::uin/888888888888:roleName/dage,qcs::cam::uin/888888888888:saml-provider/example-provider-idp",
		"qcs::cam::uin/888888888888:saml-provider/example-provider-idp,qcs::cam::uin/888888888888:roleName/dage",
	}

	tencentcloudRoles, err := ParseCloudRoles(roles, "TencentCloud")

	assert.Nil(t, err)
	assert.Len(t, tencentcloudRoles, 2)

	for _, tencentcloudRole := range tencentcloudRoles {
		assert.Equal(t, "qcs::cam::uin/888888888888:saml-provider/example-provider-idp", tencentcloudRole.PrincipalARN)
		assert.Equal(t, "qcs::cam::uin/888888888888:roleName/dage", tencentcloudRole.RoleARN)
	}

	roles = []string{""}
	tencentcloudRoles, err = ParseCloudRoles(roles, "TencentCloud")

	assert.NotNil(t, err)
	assert.Nil(t, tencentcloudRoles)

}
