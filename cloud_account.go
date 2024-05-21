package saml2aws

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/cloud"
)

// CloudAccount holds the AWS account name and roles
type CloudAccount struct {
	Name  string
	Roles []*CloudRole
}

// ParseCloudAccounts extract the aws accounts from the saml assertion
func ParseCloudAccounts(provider cloud.Provider, audience string, samlAssertion string) ([]*CloudAccount, error) {

	switch provider {
	case cloud.AWS:
		res, err := http.PostForm(audience, url.Values{"SAMLResponse": {samlAssertion}})
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving cloud SAML login form")
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
		}

		data, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving AWS login body")
		}
		return ExtractAWSAccounts(data)
	case cloud.TencentCloud:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported cloud provider: %s", provider)
	}
}

// ExtractAWSAccounts extract the accounts from the AWS html page
func ExtractAWSAccounts(data []byte) ([]*CloudAccount, error) {
	accounts := make([]*CloudAccount, 0)

	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("fieldset > div.saml-account").Each(func(i int, s *goquery.Selection) {
		account := new(CloudAccount)
		account.Name = s.Find("div.saml-account-name").Text()
		s.Find("label").Each(func(i int, s *goquery.Selection) {
			role := new(CloudRole)
			role.Name = s.Text()
			role.RoleARN, _ = s.Attr("for")
			account.Roles = append(account.Roles, role)
		})
		accounts = append(accounts, account)
	})

	return accounts, nil
}

// AssignPrincipals assign principal from roles
func AssignPrincipals(awsRoles []*CloudRole, cloudAccounts []*CloudAccount) {

	awsPrincipalARNs := make(map[string]string)
	for _, awsRole := range awsRoles {
		awsPrincipalARNs[awsRole.RoleARN] = awsRole.PrincipalARN
	}

	for _, awsAccount := range cloudAccounts {
		for _, awsRole := range awsAccount.Roles {
			awsRole.PrincipalARN = awsPrincipalARNs[awsRole.RoleARN]
		}
	}

}

// LocateRole locate role by name
func LocateRole(awsRoles []*CloudRole, roleName string) (*CloudRole, error) {
	for _, awsRole := range awsRoles {
		if awsRole.RoleARN == roleName {
			return awsRole, nil
		}
	}

	return nil, fmt.Errorf("Supplied RoleArn not found in saml assertion: %s", roleName)
}
