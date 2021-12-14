package auth

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/zalando/go-keyring"
)

var ErrSettingNotFound = fmt.Errorf("setting not found")

// Storage provides an interface for saving and loading values across runs
type Storage interface {
	// Set password in keyring for user.
	Set(service, setting, value string) error
	// Get password from keyring given service and user name.
	Get(service, setting string) (string, error)
	// Delete secret from keyring.
	Delete(service, setting string) error
}

// KeyringStorage stores in secure local storage system
// note: this requires the appropriate environment and tools be installed
// on the local machine and may not work properly in docker or headless
type KeyringStorage struct {
}

// NewKeyringStorage creates a new instance of keyring persistence
func NewKeyringStorage() Storage {
	return &KeyringStorage{}
}

// Set password in keyring for user.
func (p *KeyringStorage) Set(service, setting, value string) error {
	return keyring.Set(service, setting, value)
}

// Get password from keyring given service and user name.
func (p *KeyringStorage) Get(service, setting string) (string, error) {
	if val, err := keyring.Get(service, setting); err != nil {
		if err == keyring.ErrNotFound {
			return "", ErrSettingNotFound
		} else {
			return "", err
		}
	} else {
		return val, nil
	}
}

// Delete secret from keyring.
func (p *KeyringStorage) Delete(service, setting string) error {
	if err := keyring.Delete(service, setting); err != nil {
		if err == keyring.ErrNotFound {
			return ErrSettingNotFound
		} else {
			return err
		}
	}
	return nil
}

// EphemeralStorage stores state in memory and it is lost when the process
// ends. However, refresh tokens are persisted through the duration of the process.
type EphemeralStorage struct {
	memStore map[string]map[string]string
}

// Set stores user and pass in the keyring under the defined service
// name.
func (p *EphemeralStorage) Set(service, user, pass string) error {
	if p.memStore == nil {
		p.memStore = make(map[string]map[string]string)
	}
	if p.memStore[service] == nil {
		p.memStore[service] = make(map[string]string)
	}
	p.memStore[service][user] = pass
	return nil
}

// Get gets a secret from the keyring given a service name and a user.
func (p *EphemeralStorage) Get(service, user string) (string, error) {
	if b, ok := p.memStore[service]; ok {
		if v, ok := b[user]; ok {
			return v, nil
		}
	}
	return "", ErrSettingNotFound
}

// Delete deletes a secret, identified by service & user, from the keyring.
func (p *EphemeralStorage) Delete(service, user string) error {
	if p.memStore != nil {
		if _, ok := p.memStore[service]; ok {
			if _, ok := p.memStore[service][user]; ok {
				delete(p.memStore[service], user)
				return nil
			}
		}
	}
	return ErrSettingNotFound
}

func NewEphemeralStorage() Storage {
	return &EphemeralStorage{}
}

// FileStorage state is stored in a regular file and is not as
// secure as the Keyring persistence
type FileStorage struct {
	filename string
}

func NewFileStorage(filename string) Storage {
	return &FileStorage{filename: filename}
}

type savedCredentials map[string]map[string]string

func (p *FileStorage) load() (savedCredentials, error) {
	creds := savedCredentials{}
	if f, err := os.Open(p.filename); err != nil && !os.IsNotExist(err) {
		return nil, err
	} else if os.IsNotExist(err) {
		// new settings
		return creds, nil
	} else if err := json.NewDecoder(f).Decode(&creds); err != nil {
		_ = f.Close()
		return nil, err
	} else if err := f.Close(); err != nil {
		return nil, err
	} else {
		return creds, nil
	}
}

func (p *FileStorage) save(credentials savedCredentials) error {
	if f, err := os.Create(p.filename); err != nil {
		return err
	} else if err := json.NewEncoder(f).Encode(credentials); err != nil {
		_ = f.Close()
		return err
	} else if err := f.Close(); err != nil {
		return err
	} else {
		return nil
	}
}

// Set password in keyring for user
func (p *FileStorage) Set(service, setting, value string) error {
	creds, err := p.load()
	if err != nil {
		return err
	}
	if _, ok := creds[service]; !ok {
		creds[service] = map[string]string{}
	}
	creds[service][setting] = value
	return p.save(creds)
}

// Get setting given service and setting name
func (p *FileStorage) Get(service, setting string) (string, error) {
	if creds, err := p.load(); err != nil {
		return "", err
	} else if svc, ok := creds[service]; !ok {
		return "", ErrSettingNotFound
	} else if val, ok := svc[setting]; !ok {
		return "", ErrSettingNotFound
	} else {
		return val, nil
	}
}

// Delete setting
func (p *FileStorage) Delete(service, setting string) error {
	creds, err := p.load()
	if err != nil {
		return err
	}
	if svc, ok := creds[service]; !ok {
		return ErrSettingNotFound
	} else if _, ok := svc[setting]; !ok {
		return ErrSettingNotFound
	} else {
		delete(creds[service], setting)
		return p.save(creds)
	}
}
