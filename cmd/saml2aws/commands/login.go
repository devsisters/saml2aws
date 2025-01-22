package commands

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common/profile"
	tcsts "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/sts/v20180813"
	"github.com/versent/saml2aws/v2"
	"github.com/versent/saml2aws/v2/helper/credentials"
	"github.com/versent/saml2aws/v2/pkg/awsconfig"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/cloud"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/flags"
	"github.com/versent/saml2aws/v2/pkg/samlcache"
	"github.com/versent/saml2aws/v2/pkg/tcconfig"
)

// Login login to ADFS
func Login(loginFlags *flags.LoginExecFlags) error {

	logger := logrus.WithField("command", "login")

	account, err := buildIdpAccount(loginFlags)
	if err != nil {
		return errors.Wrap(err, "Error building login details.")
	}

	// creates a cacheProvider, only used when --cache is set
	cacheProvider := &samlcache.SAMLCacheProvider{
		Account:  account.Name,
		Filename: account.SAMLCacheFile,
	}

	loginDetails, err := resolveLoginDetails(account, loginFlags)
	if err != nil {
		return err
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
		return errors.New("Response did not contain a valid SAML assertion.")
	}

	if !loginFlags.CommonFlags.DisableKeychain {
		err = credentials.SaveCredentials(loginDetails.URL, loginDetails.Username, loginDetails.Password)
		if err != nil {
			return errors.Wrap(err, "Error storing password in keychain.")
		}
	}

	// log.Println("SAML assertion:", samlAssertion)

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

	role, err := selectCloudRole(samlAssertions, account)
	if err != nil {
		return errors.Wrap(err, "Error resolving role.")
	}
	log.Println("Selected role:", role.RoleARN)

	switch role.Provider {
	case cloud.AWS:
		creds, err := assumeAwsRoleWithSAML(account, role, samlAssertions[role.Provider])
		if err != nil {
			return errors.Wrap(err, "Error logging into AWS role using SAML assertion.")
		}
		cp := awsconfig.NewSharedCredentials(account.Profile, account.CredentialsFile)
		if err := cp.Save(creds); err != nil {
			return err
		}

		log.Println("Logged in as:", creds.PrincipalARN)
		log.Println("")
		log.Println("Your new access key pair has been stored in the AWS configuration.")
		log.Printf("Note that it will expire at %v", creds.Expires)
		if account.Profile != "default" {
			log.Println("To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile", account.Profile, "ec2 describe-instances).")
		}
	case cloud.TencentCloud:
		creds, err := assumeTencentRoleWithSAML(account, role, samlAssertions[role.Provider])
		if err != nil {
			return errors.Wrap(err, "Error logging into TencentCloud role using SAML assertion.")
		}
		cp := tcconfig.NewSharedCredentials(account.Profile, account.CredentialsFile)
		if err := cp.Save(creds); err != nil {
			return err
		}

		log.Println("Logged in as:", creds.PrincipalARN)
		log.Println("")
		log.Println("Your new secret key pair has been stored in the TencentCloud configuration.")
		log.Printf("Note that it will expire at %v", creds.Expires)
		if account.Profile != "default" {
			log.Println("To use this credential, call the TC CLI with the --profile option (e.g. tccli --profile", account.Profile, "cvm DescribeInstances).")
		}
	default:
		return errors.Wrap(err, "Error resolving role (unknown provider).")
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

	if err := account.Validate(); err != nil {
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

func selectCloudRole(samlAssertions map[cloud.Provider]string, account *cfg.IDPAccount) (*saml2aws.CloudRole, error) {
	cloudRoles := make([]*saml2aws.CloudRole, 0)
	for cloudProvider, assertion := range samlAssertions {
		data, err := b64.StdEncoding.DecodeString(assertion)
		if err != nil {
			return nil, errors.Wrap(err, "Error decoding SAML assertion.")
		}

		roleArns, err := saml2aws.ExtractCloudRoles(data)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("Error extracting %v roles arns.", cloudProvider))
		}
		if len(roleArns) == 0 {
			log.Println("No", cloudProvider, "roles to assume.")
			continue
		}

		roles, err := saml2aws.ParseCloudRoles(roleArns, cloudProvider)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("Error parsing %v roles.", cloudProvider))
		}

		if cloudProvider == cloud.AWS {
			roles, err = saml2aws.AssignAWSAccounts(roles, data, assertion)
			if err != nil {
				return nil, errors.Wrap(err, "Error assigning AWS accounts to roles.")
			}
		}

		cloudRoles = append(cloudRoles, roles...)
	}

	if len(cloudRoles) == 0 {
		log.Println("Please check you are permitted to assume roles for the AWS or TencentCloud service.")
		os.Exit(1)
	}

	return resolveRole(cloudRoles, account)
}

func resolveRole(cloudRoles []*saml2aws.CloudRole, account *cfg.IDPAccount) (role *saml2aws.CloudRole, err error) {
	if len(cloudRoles) == 1 {
		if account.RoleARN != "" {
			return saml2aws.LocateRole(cloudRoles, account.RoleARN)
		}
		return cloudRoles[0], nil
	} else if len(cloudRoles) == 0 {
		return nil, errors.New("No roles available.")
	}

	if account.RoleARN != "" {
		return saml2aws.LocateRole(cloudRoles, account.RoleARN)
	}

	for {
		role, err = saml2aws.PromptForCloudRoleSelection(cloudRoles)
		if err == nil {
			break
		}
		log.Println("Error selecting role. Try again.")
	}

	return role, nil
}

func assumeAwsRoleWithSAML(account *cfg.IDPAccount, role *saml2aws.CloudRole, samlAssertion string) (*awsconfig.AWSCredentials, error) {

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

func assumeTencentRoleWithSAML(account *cfg.IDPAccount, role *saml2aws.CloudRole, samlAssertion string) (*tcconfig.TCCredentials, error) {

	credential := common.NewCredential("", "")

	clientProfile := profile.NewClientProfile()

	client, err := tcsts.NewClient(credential, "", clientProfile)
	if err != nil {
		log.Fatalf("Failed to create sts client: %v", err)
	}
	region, ok := convertAWSRegionToTencentCloud(account.Region)
	if !ok {
		log.Println("Selected region %v is unknown or not available in TencentCloud. Selecting %v in best effort.", account.Region, region)
	}
	client.Init(region)

	log.Println("Requesting TencentCloud credentials using SAML assertion.")

	samlRequest := tcsts.NewAssumeRoleWithSAMLRequest()
	sessionDuration := uint64(account.SessionDuration)
	samlRequest.SAMLAssertion = &samlAssertion
	samlRequest.PrincipalArn = &role.PrincipalARN
	samlRequest.RoleArn = &role.RoleARN
	samlRequest.DurationSeconds = &sessionDuration
	samlRequest.RoleSessionName = &account.Username

	// log.Println(fmt.Sprintf("tccli sts AssumeRoleWithSAML --PrincipalArn %v --RoleArn %v --SAMLAssertion %v --DurationSeconds %v --RoleSessionName %v", role.PrincipalARN, role.RoleARN, samlAssertion, sessionDuration, account.Username))

	resp, err := client.AssumeRoleWithSAML(samlRequest)
	if err != nil {
		return nil, errors.Wrap(err, "Error retrieving STS credentials using SAML.")
	}

	return &tcconfig.TCCredentials{
		SecretID:     aws.StringValue(resp.Response.Credentials.TmpSecretId),
		SecretKey:    aws.StringValue(resp.Response.Credentials.TmpSecretKey),
		Token:        aws.StringValue(resp.Response.Credentials.Token),
		Region:       account.Region,
		Expires:      aws.StringValue(resp.Response.Expiration),
		PrincipalARN: role.PrincipalARN,
	}, nil
}

// convertAWSRegionToTencentCloud converts AWS regions to TencentCloud regions. Returns the TencentCloud region and a boolean indicating if the region is directly supported in TencentCloud.
func convertAWSRegionToTencentCloud(region string) (string, bool) {
	switch region {
	case "us-east-1":
		return "na-ashburn", true
	case "us-east-2":
		return "na-toronto", true
	case "us-west-1":
		return "na-siliconvalley", true
	case "us-west-2":
		return "na-siliconvalley", false
	case "af-south-1":
		return "ap-mumbai", false
	case "ap-east-1":
		return "ap-hongkong", true
	case "ap-south-1":
		return "ap-mumbai", true
	case "ap-south-2":
		return "ap-mumbai", false
	case "ap-southeast-1":
		return "ap-singapore", true
	case "ap-southeast-2":
		return "ap-jakarta", false
	case "ap-southeast-3":
		return "ap-jakarta", true
	case "ap-southeast-4":
		return "ap-jakarta", false
	case "ap-northeast-1":
		return "ap-tokyo", true
	case "ap-northeast-2":
		return "ap-seoul", true
	case "ap-northeast-3":
		return "ap-tokyo", false
	case "ca-central-1":
		return "na-toronto", false
	case "ca-west-1":
		return "na-siliconvalley", false
	case "eu-central-1":
		return "eu-frankfurt", true
	case "eu-central-2":
		return "eu-frankfurt", false
	case "eu-west-1":
		return "eu-frankfurt", false
	case "eu-west-2":
		return "eu-frankfurt", false
	case "eu-south-1":
		return "eu-frankfurt", false
	case "eu-south-2":
		return "eu-frankfurt", false
	case "eu-north-1":
		return "eu-frankfurt", false
	case "il-central-1":
		return "ap-mumbai", false
	case "me-south-1":
		return "ap-mumbai", false
	case "me-central-1":
		return "ap-mumbai", false
	case "sa-east-1":
		return "sa-saopaulo", true
	default:
		return "ap-tokyo", false
	}
}
