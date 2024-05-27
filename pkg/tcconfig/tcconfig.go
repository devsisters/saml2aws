package tcconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"

	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
)

var (
	ErrCredentialsHomeNotFound = errors.New("user home directory not found")
	ErrCredentialsNotFound     = errors.New("tc credentials not found")
)

type TCCredentials struct {
	SecretID     string `json:"secretId,omitempty"`
	SecretKey    string `json:"secretKey,omitempty"`
	Token        string `json:"token,omitempty"`
	Region       string `json:"region,omitempty"`
	Expires      string `json:"x_security_token_expires,omitempty"`
	PrincipalARN string `json:"-"`
}

type CredentialsProvider struct {
	Filename string
	Profile  string
}

func NewSharedCredentials(profile string, filename string) *CredentialsProvider {
	return &CredentialsProvider{
		Filename: filename,
		Profile:  profile,
	}
}

func (p *CredentialsProvider) Save(creds *TCCredentials) error {
	filename, err := p.resolveFilename()
	if err != nil {
		return err
	}

	if _, err = os.Stat(filename); err != nil {
		if os.IsNotExist(err) {
			dir := filepath.Dir(filename)
			if err = os.MkdirAll(dir, os.ModePerm); err != nil {
				return err
			}
		}
	}

	bytes, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return errors.Wrap(err, "unable to marshal credentials")
	}
	bytes = append(bytes, '\n')

	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Wrap(err, "unable to load file")
	}
	if _, err := file.Write(bytes); err != nil {
		return errors.Wrap(err, "unable to write to file")
	}
	defer file.Close()

	return nil
}

func (p *CredentialsProvider) resolveFilename() (string, error) {
	if p.Filename == "" {
		filename, err := p.locateConfigFile()
		if err != nil {
			return "", err
		}
		p.Filename = filename
	}

	return p.Filename, nil
}

func (p *CredentialsProvider) locateConfigFile() (string, error) {
	filename := os.Getenv("TENCENTCLOUD_CREDENTIALS_FILE")
	if filename != "" {
		return filename, nil
	}

	// Default location for credentials file is ~/.tccli/{profile}.credentials
	var name string
	var err error
	if runtime.GOOS == "windows" {
		panic("error locating credentials file on windows: not implemented")
	} else {
		if name, err = homedir.Expand("~/.tccli/" + p.Profile + ".credential"); err != nil {
			return "", ErrCredentialsHomeNotFound
		}
		// log.Println("config file:", name)
	}

	if name, err = resolveSymlink(name); err != nil {
		return "", errors.Wrap(err, "unable to resolve symlink")
	}

	return name, nil
}

func resolveSymlink(filename string) (string, error) {
	sympath, err := filepath.EvalSymlinks(filename)
	if os.IsNotExist(err) {
		return filename, nil
	}
	if err != nil {
		return "", err
	}
	return sympath, nil
}
