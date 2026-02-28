package yara

import (
	"context"
	"red-baron-edr/utils"
	"sync"
	"path/filepath"
	"io/fs"
	"strings"

	"github.com/fsnotify/fsnotify"
	// ... other imports ...
)

func MonitorFiles(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	// Initialize YARA rules once
	if compiledRules == nil {
		compiledRules = InitializeYARARules()
		if compiledRules == nil {
			utils.Logger.Error("Failed to initialize YARA rules.")
			return
		}
	}

	watcher := GetWatcher()
	if watcher == nil {
		utils.Logger.Error("Watcher is not initialized.")
		return
	}

	for {
		select {
		case <-ctx.Done():
			// Handle cleanup and exit
			utils.Logger.Info("YARA Monitor shutting down...")
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Create|fsnotify.Write) != 0 {
				utils.Logger.Debugf("File modified or created: %s", event.Name)
				RunYARARules(event.Name) // Use the pre-compiled rules
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			utils.Logger.Errorf("Watcher error: %v", err)
		}
	}
}

func RunStaticScan(ctx context.Context, root string) {
    utils.Logger.Infof("Starting static filesystem scan on: %s", root)

	// Initialize YARA rules once
	if compiledRules == nil {
		compiledRules = InitializeYARARules()
		if compiledRules == nil {
			utils.Logger.Error("Failed to initialize YARA rules.")
			return
		}
	}

    err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			select {
			case <-ctx.Done():
				return filepath.SkipAll // Immediately stop walking if EDR stops
			default:
			if err != nil {
				// Permission denied is common in /root or /proc, just skip and continue
				return nil 
			}

			// 1. Skip the quarantine directory to avoid scanning "captured" threats
			if strings.HasPrefix(path, "/tmp/quarantine") {
				return filepath.SkipDir
			}

			// 2. Only scan files, not directories
			if !d.IsDir() {
				utils.Logger.Debugf("Static scanning: %s", path)
				RunYARARules(path)
			}
			return nil
		}
    })

    if err != nil {
        utils.Logger.Errorf("Static scan encountered an error: %v", err)
    }

    utils.Logger.Info("Static filesystem scan completed.")
}

