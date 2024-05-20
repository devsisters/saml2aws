package commands

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2"
	"github.com/versent/saml2aws/v2/helper/credentials"
	"github.com/versent/saml2aws/v2/pkg/awsconfig"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/cloud"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/flags"
	"github.com/versent/saml2aws/v2/pkg/samlcache"
)

// Login login to ADFS
func Login(loginFlags *flags.LoginExecFlags) error {

	logger := logrus.WithField("command", "login")

	account, err := buildIdpAccount(loginFlags)
	if err != nil {
		return errors.Wrap(err, "Error building login details.")
	}

	sharedCreds := awsconfig.NewSharedCredentials(account.Profile, account.CredentialsFile)
	// creates a cacheProvider, only used when --cache is set
	cacheProvider := &samlcache.SAMLCacheProvider{
		Account:  account.Name,
		Filename: account.SAMLCacheFile,
	}

	logger.Debug("Check if creds exist.")

	// this checks if the credentials file has been created yet
	exist, err := sharedCreds.CredsExists()
	if err != nil {
		return errors.Wrap(err, "Error loading credentials.")
	}
	if !exist {
		log.Println("Unable to load credentials. Login required to create them.")
		return nil
	}

	if !sharedCreds.Expired() && !loginFlags.Force {
		logger.Debug("Credentials are not expired. Skipping.")
		previousCreds, err := sharedCreds.Load()
		if err != nil {
			log.Println("Unable to load cached credentials.")
		} else {
			logger.Debug("Credentials will expire at ", previousCreds.Expires)
		}
		if loginFlags.CredentialProcess {
			err = PrintCredentialProcess(previousCreds)
			if err != nil {
				return err
			}
		}
		return nil
	}

	loginDetails, err := resolveLoginDetails(account, loginFlags)
	if err != nil {
		log.Printf("%+v", err)
		os.Exit(1)
	}

	logger.WithField("idpAccount", account).Debug("building samlProvider")

	provider, err := saml2aws.NewSAMLClient(account)
	if err != nil {
		return errors.Wrap(err, "Error building IdP client.")
	}

	err = provider.Validate(loginDetails)
	if err != nil {
		return errors.Wrap(err, "Error validating login details.")
	}

	var samlAssertion string
	if account.SAMLCache {
		if cacheProvider.IsValid() {
			samlAssertion, err = cacheProvider.ReadRaw()
			if err != nil {
				return errors.Wrap(err, "Could not read SAML cache.")
			}
		} else {
			logger.Debug("Cache is invalid")
			log.Printf("Authenticating as %s ...", loginDetails.Username)
		}
	} else {
		log.Printf("Authenticating as %s ...", loginDetails.Username)
	}

	if samlAssertion == "" {
		// samlAssertion was not cached
		samlAssertion, err = provider.Authenticate(loginDetails)
		if err != nil {
			return errors.Wrap(err, "Error authenticating to IdP.")
		}
		if account.SAMLCache {
			err = cacheProvider.WriteRaw(samlAssertion)
			if err != nil {
				return errors.Wrap(err, "Could not write SAML cache.")
			}
		}
	}

	if samlAssertion == "" {
		log.Println("Response did not contain a valid SAML assertion.")
		log.Println("Please check that your username and password is correct.")
		log.Println("To see the output follow the instructions in https://github.com/versent/saml2aws#debugging-issues-with-idps")
		os.Exit(1)
	}

	if !loginFlags.CommonFlags.DisableKeychain {
		err = credentials.SaveCredentials(loginDetails.URL, loginDetails.Username, loginDetails.Password)
		if err != nil {
			return errors.Wrap(err, "Error storing password in keychain.")
		}
	}

	log.Println("SAML assertion:", samlAssertion)

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

	role, err := selectAwsRole(samlAssertions, account)
	if err != nil {
		return errors.Wrap(err, "Error resolving role.")
	}
	log.Println("Selected role:", role.RoleARN)

	awsCreds, err := loginToStsUsingRole(account, role, samlAssertion)
	if err != nil {
		return errors.Wrap(err, "Error logging into AWS role using SAML assertion.")
	}

	// print credential process if needed
	if loginFlags.CredentialProcess {
		err = PrintCredentialProcess(awsCreds)
		if err != nil {
			return err
		}
	} else {
		err = saveCredentials(awsCreds, sharedCreds)
		if err != nil {
			return err
		}

		log.Println("Logged in as:", awsCreds.PrincipalARN)
		log.Println("")
		log.Println("Your new access key pair has been stored in the AWS configuration.")
		log.Printf("Note that it will expire at %v", awsCreds.Expires)
		if sharedCreds.Profile != "default" {
			log.Println("To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile", sharedCreds.Profile, "ec2 describe-instances).")
		}
	}

	return nil
}

func buildIdpAccount(loginFlags *flags.LoginExecFlags) (*cfg.IDPAccount, error) {
	cfgm, err := cfg.NewConfigManager(loginFlags.CommonFlags.ConfigFile)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load configuration.")
	}

	account, err := cfgm.LoadIDPAccount(loginFlags.CommonFlags.IdpAccount)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load IdP account.")
	}

	// update username and hostname if supplied
	flags.ApplyFlagOverrides(loginFlags.CommonFlags, account)

	err = account.Validate()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to validate account.")
	}

	return account, nil
}

func resolveLoginDetails(account *cfg.IDPAccount, loginFlags *flags.LoginExecFlags) (*creds.LoginDetails, error) {

	// log.Printf("loginFlags %+v", loginFlags)

	loginDetails := &creds.LoginDetails{URL: account.URL, TencentCloudURL: account.TencentCloudURL, Username: account.Username, MFAToken: loginFlags.CommonFlags.MFAToken, DuoMFAOption: loginFlags.DuoMFAOption}

	log.Printf("Using IdP Account %s to access %s %s", loginFlags.CommonFlags.IdpAccount, account.Provider, account.URL)

	var err error
	if !loginFlags.CommonFlags.DisableKeychain {
		err = credentials.LookupCredentials(loginDetails, account.Provider)
		if err != nil {
			if !credentials.IsErrCredentialsNotFound(err) {
				return nil, errors.Wrap(err, "Error loading saved password.")
			}
		}
	} else { // if user disabled keychain, dont use Okta sessions & dont remember Okta MFA device
		if strings.ToLower(account.Provider) == "okta" {
			account.DisableSessions = true
			account.DisableRememberDevice = true
		}
	}

	// log.Printf("%s %s", savedUsername, savedPassword)

	// if you supply a username in a flag it takes precedence
	if loginFlags.CommonFlags.Username != "" {
		loginDetails.Username = loginFlags.CommonFlags.Username
	}

	// if you supply a password in a flag it takes precedence
	if loginFlags.CommonFlags.Password != "" {
		loginDetails.Password = loginFlags.CommonFlags.Password
	}

	// if you supply a cleint_id in a flag it takes precedence
	if loginFlags.CommonFlags.ClientID != "" {
		loginDetails.ClientID = loginFlags.CommonFlags.ClientID
	}

	// if you supply a client_secret in a flag it takes precedence
	if loginFlags.CommonFlags.ClientSecret != "" {
		loginDetails.ClientSecret = loginFlags.CommonFlags.ClientSecret
	}

	// if you supply an mfa_ip_address in a flag or an IDP account it takes precedence
	if account.MFAIPAddress != "" {
		loginDetails.MFAIPAddress = account.MFAIPAddress
	} else if loginFlags.CommonFlags.MFAIPAddress != "" {
		loginDetails.MFAIPAddress = loginFlags.CommonFlags.MFAIPAddress
	}

	if loginFlags.DownloadBrowser {
		loginDetails.DownloadBrowser = loginFlags.DownloadBrowser
	} else if account.DownloadBrowser {
		loginDetails.DownloadBrowser = account.DownloadBrowser
	}

	// log.Printf("loginDetails %+v", loginDetails)

	// if skip prompt was passed just pass back the flag values
	if loginFlags.CommonFlags.SkipPrompt || loginFlags.CredentialProcess {
		return loginDetails, nil
	}

	if account.Provider != "Shell" {
		err = saml2aws.PromptForLoginDetails(loginDetails, account.Provider)
		if err != nil {
			return nil, errors.Wrap(err, "Error occurred accepting input.")
		}
	}

	return loginDetails, nil
}

func selectAwsRole(samlAssertions map[cloud.Provider]string, account *cfg.IDPAccount) (*saml2aws.CloudRole, error) {
	cloudRoles := make([]*saml2aws.CloudRole, 0)
	for cloud, assertion := range samlAssertions {
		data, err := b64.StdEncoding.DecodeString(assertion)
		if err != nil {
			return nil, errors.Wrap(err, "Error decoding SAML assertion.")
		}

		roleArns, err := saml2aws.ExtractCloudRoles(data)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("Error extracting %v roles arns.", cloud))
		}
		if len(roleArns) == 0 {
			log.Println("No", cloud, "roles to assume.")
			continue
		}

		cloudRoles, err := saml2aws.ParseCloudRoles(roleArns, cloud)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("Error parsing %v roles.", cloud))
		}
		cloudRoles = append(cloudRoles, cloudRoles...)
	}

	if len(cloudRoles) == 0 {
		log.Println("Please check you are permitted to assume roles for the AWS or TencentCloud service.")
		os.Exit(1)
	}

	return resolveRole(cloudRoles, samlAssertions, account)
}

func resolveRole(cloudRoles []*saml2aws.CloudRole, samlAssertions map[cloud.Provider]string, account *cfg.IDPAccount) (role *saml2aws.CloudRole, err error) {
	if len(cloudRoles) == 1 {
		if account.RoleARN != "" {
			return saml2aws.LocateRole(cloudRoles, account.RoleARN)
		}
		return cloudRoles[0], nil
	} else if len(cloudRoles) == 0 {
		return nil, errors.New("No roles available.")
	}

	cloudAccounts := make([]*saml2aws.CloudAccount, 0)
	for provider, assertion := range samlAssertions {
		data, err := b64.StdEncoding.DecodeString(assertion)
		if err != nil {
			return nil, errors.Wrap(err, "Error decoding SAML assertion.")
		}

		aud, err := saml2aws.ExtractDestinationURL(data)
		if err != nil {
			return nil, errors.Wrap(err, "Error parsing destination URL.")
		}

		accounts, err := saml2aws.ParseCloudAccounts(provider, aud, assertion)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("Error parsing %v role accounts.", provider))
		}

		saml2aws.AssignPrincipals(cloudRoles, accounts)
		cloudAccounts = append(cloudAccounts, accounts...)
	}

	if len(cloudAccounts) == 0 {
		return nil, errors.New("No accounts available.")
	}

	if account.RoleARN != "" {
		return saml2aws.LocateRole(cloudRoles, account.RoleARN)
	}

	for {
		role, err = saml2aws.PromptForAWSRoleSelection(cloudAccounts)
		if err == nil {
			break
		}
		log.Println("Error selecting role. Try again.")
	}

	return role, nil
}

func loginToStsUsingRole(account *cfg.IDPAccount, role *saml2aws.CloudRole, samlAssertion string) (*awsconfig.AWSCredentials, error) {

	sess, err := session.NewSession(&aws.Config{
		Region: &account.Region,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create session.")
	}

	svc := sts.New(sess)

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(role.PrincipalARN), // Required
		RoleArn:         aws.String(role.RoleARN),      // Required
		SAMLAssertion:   aws.String(samlAssertion),     // Required
		DurationSeconds: aws.Int64(int64(account.SessionDuration)),
	}

	log.Println("Requesting AWS credentials using SAML assertion.")

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		return nil, errors.Wrap(err, "Error retrieving STS credentials using SAML.")
	}

	return &awsconfig.AWSCredentials{
		AWSAccessKey:     aws.StringValue(resp.Credentials.AccessKeyId),
		AWSSecretKey:     aws.StringValue(resp.Credentials.SecretAccessKey),
		AWSSessionToken:  aws.StringValue(resp.Credentials.SessionToken),
		AWSSecurityToken: aws.StringValue(resp.Credentials.SessionToken),
		PrincipalARN:     aws.StringValue(resp.AssumedRoleUser.Arn),
		Expires:          resp.Credentials.Expiration.Local(),
		Region:           account.Region,
	}, nil
}

func saveCredentials(awsCreds *awsconfig.AWSCredentials, sharedCreds *awsconfig.CredentialsProvider) error {
	err := sharedCreds.Save(awsCreds)
	if err != nil {
		return errors.Wrap(err, "Error saving credentials.")
	}

	return nil
}

// CredentialsToCredentialProcess
// Returns a Json output that is compatible with the AWS credential_process
// https://github.com/awslabs/awsprocesscreds
func CredentialsToCredentialProcess(awsCreds *awsconfig.AWSCredentials) (string, error) {

	type AWSCredentialProcess struct {
		Version         int
		AccessKeyId     string
		SecretAccessKey string
		SessionToken    string
		Expiration      string
	}

	cred_process := AWSCredentialProcess{
		Version:         1,
		AccessKeyId:     awsCreds.AWSAccessKey,
		SecretAccessKey: awsCreds.AWSSecretKey,
		SessionToken:    awsCreds.AWSSessionToken,
		Expiration:      awsCreds.Expires.Format(time.RFC3339),
	}

	p, err := json.Marshal(cred_process)
	if err != nil {
		return "", errors.Wrap(err, "Error while marshalling the credential process.")
	}
	return string(p), nil

}

// PrintCredentialProcess Prints a Json output that is compatible with the AWS credential_process
// https://github.com/awslabs/awsprocesscreds
func PrintCredentialProcess(awsCreds *awsconfig.AWSCredentials) error {
	jsonData, err := CredentialsToCredentialProcess(awsCreds)
	if err == nil {
		fmt.Println(jsonData)
	}
	return err
}
