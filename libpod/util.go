package libpod

import (
	"path/filepath"
	"os"
)

// WriteFile writes a provided string to a provided path
func WriteFile(content string, path string) error {
	baseDir := filepath.Dir(path)
	if baseDir != "" {
		if _, err := os.Stat(path); err != nil{
			return err
		}
	}
	f, err := os.Create(path)
	defer f.Close()
	if err != nil{
		return err
	}
	f.WriteString(content)
	f.Sync()
	return nil
}