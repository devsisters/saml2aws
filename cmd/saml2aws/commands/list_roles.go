package commands

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2"
	"github.com/versent/saml2aws/v2/helper/credentials"
	"github.com/versent/saml2aws/v2/pkg/flags"
	"github.com/versent/saml2aws/v2/pkg/samlcache"
)

// ListRoles will list available role ARNs
func ListRoles(loginFlags *flags.LoginExecFlags) error {

	logger := logrus.WithField("command", "list")

	account, err := buildIdpAccount(loginFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	// creates a cacheProvider, only used when --cache is set
	cacheProvider := &samlcache.SAMLCacheProvider{
		Account:  account.Name,
		Filename: account.SAMLCacheFile,
	}

	loginDetails, err := resolveLoginDetails(account, loginFlags)
	if err != nil {
		log.Printf("%+v", err)
		os.Exit(1)
	}

	logger.WithField("idpAccount", account).Debug("building provider")

	provider, err := saml2aws.NewSAMLClient(account)
	if err != nil {
		return errors.Wrap(err, "error building IdP client")
	}

	err = provider.Validate(loginDetails)
	if err != nil {
		return errors.Wrap(err, "error validating login details")
	}

	var samlAssertion string
	if account.SAMLCache {
		if cacheProvider.IsValid() {
			samlAssertion, err = cacheProvider.ReadRaw()
			if err != nil {
				logger.Debug("Could not read cache:", err)
			}
		} else {
			logger.Debug("Cache is invalid")
			log.Printf("Authenticating as %s ...", loginDetails.Username)
		}
	}

	if samlAssertion == "" {
		// samlAssertion was not cached
		samlAssertion, err = provider.Authenticate(loginDetails)
		if err != nil {
			return errors.Wrap(err, "error authenticating to IdP")
		}
		if account.SAMLCache {
			err = cacheProvider.WriteRaw(samlAssertion)
			if err != nil {
				logger.Error("Could not write samlAssertion:", err)
			}
		}
	}

	if samlAssertion == "" {
		log.Println("Response did not contain a valid SAML assertion")
		log.Println("Please check your username and password is correct")
		log.Println("To see the output follow the instructions in https://github.com/versent/saml2aws#debugging-issues-with-idps")
		os.Exit(1)
	}

	if !loginFlags.CommonFlags.DisableKeychain {
		err = credentials.SaveCredentials(loginDetails.URL, loginDetails.Username, loginDetails.Password)
		if err != nil {
			return errors.Wrap(err, "error storing password in keychain")
		}
	}

	samlAssertions := make(map[string]string)
	if loginDetails.TencentCloudURL != "" {
		// If TencentCloud is configured, unmarshal the SAML assertion for both AWS and TencentCloud
		if err = json.Unmarshal([]byte(samlAssertion), &samlAssertions); err != nil {
			return errors.Wrap(err, "error unmarshalling saml assertion. (Devsisters custom implementation)")
		}
	} else {
		// Only AWS is configured, proceed with normal saml2aws flow
		samlAssertions["AWS"] = samlAssertion
	}

	cloudRoles := make([]*saml2aws.CloudRole, 0)
	for cloud, assertion := range samlAssertions {
		data, err := b64.StdEncoding.DecodeString(assertion)
		if err != nil {
			return errors.Wrap(err, "error decoding SAML assertion.")
		}

		roleArns, err := saml2aws.ExtractCloudRoles(data)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("error extracting %v role arns.", cloud))
		}
		if len(roleArns) == 0 {
			log.Println("No", cloud, "roles to assume.")
			continue
		}

		cloudRoles, err := saml2aws.ParseCloudRoles(roleArns, cloud)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("error parsing %s roles", cloud))
		}
		cloudRoles = append(cloudRoles, cloudRoles...)
	}
	if len(cloudRoles) == 0 {
		os.Exit(1)
	}

	if err := listRoles(cloudRoles, samlAssertions); err != nil {
		return errors.Wrap(err, "Failed to list roles")
	}

	return nil
}

func listRoles(cloudRoles []*saml2aws.CloudRole, samlAssertions map[string]string) error {
	cloudAccounts := make([]*saml2aws.AWSAccount, 0)
	for provider, assertion := range samlAssertions {
		data, err := b64.StdEncoding.DecodeString(assertion)
		if err != nil {
			return errors.Wrap(err, "error decoding saml assertion")
		}

		aud, err := saml2aws.ExtractDestinationURL(data)
		if err != nil {
			return errors.Wrap(err, "error parsing destination url")
		}

		accounts, err := saml2aws.ParseAWSAccounts(aud, assertion)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("error parsing %v role accounts", provider))
		}

		saml2aws.AssignPrincipals(cloudRoles, accounts)
		cloudAccounts = append(cloudAccounts, accounts...)
	}

	log.Println("")
	for _, account := range cloudAccounts {
		fmt.Println(account.Name)
		for _, role := range account.Roles {
			fmt.Println(role.RoleARN)
		}
		fmt.Println("")
	}

	return nil
}
