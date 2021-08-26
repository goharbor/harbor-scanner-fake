package util

import (
	"os"
	"path"
)

const AppName = "fake-scanner"

func MkdirIfNotExists(dirname string) error {
	if _, err := os.Stat(dirname); os.IsNotExist(err) {
		err := os.MkdirAll(dirname, os.ModePerm)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func GetCacheDir() (string, error) {
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", nil
	}

	cacheDir := path.Join(userCacheDir, AppName)

	return cacheDir, MkdirIfNotExists(cacheDir)
}
