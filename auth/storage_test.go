package auth

import (
	"os"
	"testing"
)

func TestStorage(t *testing.T) {

	if err := os.RemoveAll("settings.json"); err != nil {
		t.Error(err)
	}

	tests := map[string]Storage{
		"ephemeral": NewEphemeralStorage(),
		"keyring":   NewKeyringStorage(),
		"file":      NewFileStorage("settings.json"),
	}

	defer os.RemoveAll("settings.json")

	for name, storage := range tests {
		t.Run(name, func(t *testing.T) {
			// new setting
			if err := storage.Set("myservice", "mysetting", "myvalue"); err != nil {
				t.Error(err)
			}
			if val, err := storage.Get("myservice", "mysetting"); err != nil {
				t.Error(err)
			} else if val != "myvalue" {
				t.Errorf("got %s, expected %s", val, "myvalue")
			}

			// overwrite existing
			if err := storage.Set("myservice", "mysetting", "myvalue2"); err != nil {
				t.Error(err)
			}
			if val, err := storage.Get("myservice", "mysetting"); err != nil {
				t.Error(err)
			} else if val != "myvalue2" {
				t.Errorf("got %s, expected %s", val, "myvalue2")
			}

			// delete
			if err := storage.Delete("myservice", "mysetting"); err != nil {
				t.Error(err)
			}

			// setting that doesn't exist
			if _, err := storage.Get("myservice", "doesntexist"); err != ErrSettingNotFound {
				t.Errorf("got unexpected error: %v", err)
			}

			// delete setting that doesn't exist
			if err := storage.Delete("myservice", "doesntexist"); err != ErrSettingNotFound {
				t.Errorf("got unexpected error: %v", err)
			}
		})
	}
}
