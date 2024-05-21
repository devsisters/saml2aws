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
	"github.com/versent/saml2aws/v2/pkg/cloud"
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

	samlAssertions := make(map[cloud.Provider]string)
	if loginDetails.TencentCloudURL != "" {
		// If TencentCloud is configured, unmarshal the SAML assertion for both AWS and TencentCloud
		if err = json.Unmarshal([]byte(samlAssertion), &samlAssertions); err != nil {
			return errors.Wrap(err, "error unmarshalling saml assertion. (Devsisters custom implementation)")
		}
	} else {
		// Only AWS is configured, proceed with normal saml2aws flow
		samlAssertions[cloud.AWS] = samlAssertion
	}

	cloudRoles := make([]*saml2aws.CloudRole, 0)
	for cloud, assertion := range samlAssertions {
		data, err := b64.StdEncoding.DecodeString(assertion)
		if err != nil {
			return errors.Wrap(err, "error decoding SAML assertion")
		}

		roleArns, err := saml2aws.ExtractCloudRoles(data)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("error extracting %v role arns", cloud))
		}
		if len(roleArns) == 0 {
			// log.Println("No", cloud, "roles to assyyume")
			continue
		}

		roles, err := saml2aws.ParseCloudRoles(roleArns, cloud)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("error parsing %s roles", cloud))
		}
		cloudRoles = append(cloudRoles, roles...)

		for _, role := range roles {
			fmt.Println(fmt.Sprintf("%v (%v)", role.RoleARN, cloud))
		}
	}
	if len(cloudRoles) == 0 {
		fmt.Println("No cloud provider roles to assume")
		os.Exit(1)
	}

	return nil
}
