package auth

import (
	"fmt"

	"github.com/spf13/viper"
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

// ViperStorage state is stored in viper config and saved after each change
type ViperStorage struct {
	prefix    string
	delimiter string
	v         *viper.Viper
}

func NewViperStorage(v *viper.Viper, prefix, delimiter string) Storage {
	return &ViperStorage{
		v:         v,
		prefix:    prefix,
		delimiter: delimiter,
	}
}

func (p *ViperStorage) key(service, setting string) string {
	return p.prefix + p.delimiter + service + p.delimiter + setting
}

// Set password in keyring for user
func (p *ViperStorage) Set(service, setting, value string) error {
	p.v.Set(p.key(service, setting), value)
	return nil
}

// Get setting given service and setting name
func (p *ViperStorage) Get(service, setting string) (string, error) {
	if val := p.v.GetString(p.key(service, setting)); val == "" {
		return "", ErrSettingNotFound
	} else {
		return val, nil
	}
}

// Delete setting
func (p *ViperStorage) Delete(service, setting string) error {
	if _, err := p.Get(service, setting); err != nil {
		return err
	} else {
		return p.Set(service, setting, "")
	}
}
