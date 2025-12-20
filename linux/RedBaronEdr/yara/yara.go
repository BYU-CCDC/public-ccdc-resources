package yara

import (
	"context"
	"red-baron-edr/utils"
	"sync"

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
