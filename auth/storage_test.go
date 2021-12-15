package auth

import (
	"errors"
	"os"
	"testing"

	"github.com/spf13/viper"
)

func TestStorage(t *testing.T) {

	if err := os.RemoveAll("config.yaml"); err != nil {
		t.Error(err)
	}

	v := viper.NewWithOptions(viper.KeyDelimiter("_"))
	v.SetConfigName("config") // name of config file (without extension)
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	if err := v.WriteConfigAs("config.yaml"); err != nil {
		t.Error(err)
	}
	if err := v.ReadInConfig(); err != nil && !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		t.Error(err)
	}

	tests := map[string]Storage{
		"ephemeral": NewEphemeralStorage(),
		"keyring":   NewKeyringStorage(),
		"viper":     NewViperStorage(v, "_"),
	}

	defer os.RemoveAll("config.yaml")

	const serviceName = "https://myservice"

	for name, storage := range tests {
		t.Run(name, func(t *testing.T) {
			// new setting
			if err := storage.Set(serviceName, "mysetting", "myvalue"); err != nil {
				t.Error(err)
			}
			if val, err := storage.Get(serviceName, "mysetting"); err != nil {
				t.Error(err)
			} else if val != "myvalue" {
				t.Errorf("got %s, expected %s", val, "myvalue")
			}

			// overwrite existing
			if err := storage.Set(serviceName, "mysetting", "myvalue2"); err != nil {
				t.Error(err)
			}
			if val, err := storage.Get(serviceName, "mysetting"); err != nil {
				t.Error(err)
			} else if val != "myvalue2" {
				t.Errorf("got %s, expected %s", val, "myvalue2")
			}

			// delete
			if err := storage.Delete(serviceName, "mysetting"); err != nil {
				t.Error(err)
			}

			// setting that doesn't exist
			if _, err := storage.Get(serviceName, "doesntexist"); err != ErrSettingNotFound {
				t.Errorf("got unexpected error: %v", err)
			}

			// delete setting that doesn't exist
			if err := storage.Delete(serviceName, "doesntexist"); err != ErrSettingNotFound {
				t.Errorf("got unexpected error: %v", err)
			}
		})
	}
}
