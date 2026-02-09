package yara

import (
	"io/fs"
	"path/filepath"
	"strings"

	"red-baron-edr/utils"

	"github.com/fsnotify/fsnotify"
)

var watcher *fsnotify.Watcher

// InitializeWatcher sets up the file system watcher for specific directories.
func InitializeWatcher(directories []string) error {
	var err error
	watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	for _, dir := range directories {
		if strings.HasPrefix(dir, "/tmp/quarantine") {
			utils.Logger.Debugf("Skipping quarantine directory: %s", dir)
			continue
		}
		err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				utils.Logger.Errorf("Error accessing path %s: %v", path, err)
				return nil // Skip this path and continue
			}
			if info.IsDir() {
				if strings.HasPrefix(path, "/tmp/quarantine") {
					utils.Logger.Debugf("Skipping quarantine directory: %s", path)
					return filepath.SkipDir
				}
				if err := watcher.Add(path); err != nil {
					utils.Logger.Errorf("Error watching directory %s: %v", path, err)
				}
			}
			return nil
		})
		if err != nil {
			utils.Logger.Errorf("Error walking directory %s: %v", dir, err)
			// Continue with the next directory instead of returning
		}
	}

	utils.Logger.Infof("Watcher initialized for directories: %v", directories)
	return nil
}

// GetWatcher returns the active watcher instance.
func GetWatcher() *fsnotify.Watcher {
	return watcher
}
