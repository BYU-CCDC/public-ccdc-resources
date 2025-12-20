package installer

import (
	"io"
	"os"
	"path/filepath"

	"red-baron-edr/utils"

	"github.com/charmbracelet/log"
	"github.com/kardianos/service"
)

// program implements the service.Interface
type program struct{}

// Start is called when the service is started.
func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}

// run contains the logic of the service.
func (p *program) run() {
	// Your service logic here
}

// Stop is called when the service is stopped.
func (p *program) Stop(s service.Service) error {
	// Stop should not block. Return with a few seconds.
	return nil
}

func setupService() error {
	svcConfig := &service.Config{
		Name:        "redbaronedr",
		DisplayName: "Red Baron Service",
		Description: "This is a service for Red Baron EDR.",
		Executable:  utils.RedBaronBinDir + "redbaron", // Use the directory from utils
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Error("Failed to create service", "error", err)
		return err
	}

	if err := s.Install(); err != nil {
		log.Error("Failed to install service", "error", err)
		return err
	}

	log.Info("Service installed successfully.")
	return nil
}

// RunInstallation performs the installation process.
func RunInstallation() error {
	log.Info("Starting installation...")

	// Create necessary directories using constants from utils
	directories := []string{
		utils.RedBaronBinDir,
		utils.LogDir,
		utils.EtcDir,
		utils.VarLibDir,
	}

	for _, dir := range directories {
		if err := createFolder(dir); err != nil {
			log.Error("Failed to create folder", "path", dir, "error", err)
			return err
		}
		log.Info("Folder created or already exists", "path", dir)
	}

	// Move YARA rules
	if err := moveYaraRules("yara_rules/", utils.YaraRulesDir); err != nil {
		log.Error("Failed to move YARA rules", "error", err)
		return err
	}

	// Move Rules rules
	if err := moveRules("rule_engine2/rulesV2/", utils.RulesV2Dir); err != nil {
		log.Error("Failed to move rules", "error", err)
		return err
	}

	// Move Web rules
	if err := moveWebRules("web_parser/", utils.WebRulesDir); err != nil {
		log.Error("Failed to move web rules", "error", err)
		return err
	}

	// Copy the redbaron executable
	if err := copyExecutable("./redbaron", utils.RedBaronBinDir); err != nil {
		log.Error("Failed to copy redbaron executable", "error", err)
		return err
	}

	// Setup the service
	if err := setupService(); err != nil {
		log.Error("Failed to setup service", "error", err)
		return err
	}

	log.Info("Installation completed successfully.")
	return nil
}

// createFolder creates a folder if it doesn't already exist.
func createFolder(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create the folder with appropriate permissions
		if err := os.MkdirAll(path, 0755); err != nil {
			log.Error("Failed to create folder", "path", path, "error", err)
			return err
		}
		log.Info("Folder created successfully", "path", path)
	} else if err != nil {
		log.Error("Error checking folder existence", "path", path, "error", err)
		return err
	} else {
		log.Debug("Folder already exists", "path", path)
	}

	return nil
}

// moveYaraRules moves all *.yara files from the source directory to the destination directory.
func moveYaraRules(sourceDir, destDir string) error {
	// Ensure the destination directory exists
	if err := createFolder(destDir); err != nil {
		return err
	}

	// Walk through the source directory to find *.yara files
	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Error("Error accessing file", "path", path, "error", err)
			return err
		}

		// Only process files with the .yara extension
		if !info.IsDir() && (filepath.Ext(info.Name()) == ".yara" || filepath.Ext(info.Name()) == ".yar") {
			destPath := filepath.Join(destDir, info.Name())
			log.Info("Copying YARA file", "source", path, "destination", destPath)

			// Copy the file
			if err := copyFile(path, destPath); err != nil {
				log.Error("Failed to copy YARA file", "source", path, "destination", destPath, "error", err)
				return err
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	log.Info("All YARA rules moved successfully", "destination", destDir)
	return nil
}

// moveRules moves all *.json files from the source directory to the destination directory.
func moveRules(sourceDir, destDir string) error {
	// Ensure the destination directory exists
	if err := createFolder(destDir); err != nil {
		return err
	}

	// Walk through the source directory to find *.json files
	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Error("Error accessing file", "path", path, "error", err)
			return err
		}

		// Only process files with the .yara extension
		if !info.IsDir() && filepath.Ext(info.Name()) == ".toml" {
			destPath := filepath.Join(destDir, info.Name())
			log.Info("Copying rules file", "source", path, "destination", destPath)

			// Copy the file
			if err := copyFile(path, destPath); err != nil {
				log.Error("Failed to copy rule file", "source", path, "destination", destPath, "error", err)
				return err
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	log.Info("All rules moved successfully", "destination", destDir)
	return nil
}

// moveWebRules moves all *.data files from the source directory to the destination directory.
func moveWebRules(sourceDir, destDir string) error {
	// Ensure the destination directory exists
	if err := createFolder(destDir); err != nil {
		return err
	}

	// Walk through the source directory to find *.data files
	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Error("Error accessing file", "path", path, "error", err)
			return err
		}

		// Only process files with the .data extension
		if !info.IsDir() && filepath.Ext(info.Name()) == ".data" {
			destPath := filepath.Join(destDir, info.Name())
			log.Info("Copying web rules file", "source", path, "destination", destPath)

			// Copy the file
			if err := copyFile(path, destPath); err != nil {
				log.Error("Failed to copy web rules file", "source", path, "destination", destPath, "error", err)
				return err
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	log.Info("All web rules moved successfully", "destination", destDir)
	return nil
}

// copyFile copies a file from source to destination
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	// Preserve the file permissions
	srcInfo, err := sourceFile.Stat()
	if err != nil {
		return err
	}
	return os.Chmod(dst, srcInfo.Mode())
}

// copyExecutable copies an executable to the specified directory and ensures it is executable.
func copyExecutable(sourceExecutable, destDir string) error {
	// Ensure the destination directory exists
	if err := createFolder(destDir); err != nil {
		log.Error("Failed to create destination directory", "path", destDir, "error", err)
		return err
	}

	// Extract the source file name and set the destination path
	sourceFileName := filepath.Base(sourceExecutable)
	destPath := filepath.Join(destDir, sourceFileName)

	log.Info("Copying executable", "source", sourceExecutable, "destination", destPath)

	// Copy the executable file
	if err := copyFile(sourceExecutable, destPath); err != nil {
		log.Error("Failed to copy executable", "source", sourceExecutable, "destination", destPath, "error", err)
		return err
	}

	// Ensure the file is executable
	if err := os.Chmod(destPath, 0755); err != nil {
		log.Error("Failed to set executable permissions", "path", destPath, "error", err)
		return err
	}

	log.Info("Executable copied and permissions set successfully", "destination", destPath)
	return nil
}
