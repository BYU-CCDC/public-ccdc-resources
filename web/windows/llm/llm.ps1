# For longer format competitions, are we allowed to setup small form factor llms considering it's on prem? Just experimenting: 

# Define log file
$logFile = "C:\LLM_Setup\setup_log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Function to log events
function Write-Log {
    param (
        [string]$message
    )
    Write-Output "$currentDateTime - $message" | Out-File -FilePath $logFile -Append
}

Write-Log "Starting small form factor LLM setup..."

# Step 1: Create directory for LLM setup
$llmSetupDir = "C:\LLM_Setup"
if (!(Test-Path -Path $llmSetupDir)) {
    New-Item -Path $llmSetupDir -ItemType Directory | Out-Null
    Write-Log "Created directory for LLM setup at $llmSetupDir."
}

# Step 2: Install Chocolatey (if not installed)
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Log "Chocolatey not found. Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    Write-Log "Chocolatey installed."
} else {
    Write-Log "Chocolatey is already installed."
}

# Step 3: Install Python (if not installed)
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Log "Python not found. Installing Python via Chocolatey..."
    choco install python -y
    $env:Path += ";C:\Python39\Scripts;C:\Python39\"
    Write-Log "Python installed."
} else {
    Write-Log "Python is already installed."
}

# Step 4: Install required Python packages
Write-Log "Installing required Python packages..."
python -m pip install --upgrade pip
python -m pip install torch transformers fastapi uvicorn pydantic

# Step 5: Set up a small language model (e.g., Alpaca, MiniLM, or DistilGPT2)
Write-Log "Downloading and setting up a lightweight LLM for CPU..."
$llmModelDir = "$llmSetupDir\model"
if (!(Test-Path -Path $llmModelDir)) {
    New-Item -Path $llmModelDir -ItemType Directory | Out-Null
}

# Using Hugging Face transformers to load a small model like DistilGPT2
Write-Log "Setting up script for model inference using FastAPI..."
$modelScript = @"
from fastapi import FastAPI, Request
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

app = FastAPI()

# Load lightweight model
model_name = 'distilgpt2'  # Using a small model suitable for CPU
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name)

@app.post("/generate")
async def generate_text(request: Request):
    data = await request.json()
    input_text = data.get("input_text", "")
    inputs = tokenizer(input_text, return_tensors="pt")
    with torch.no_grad():
        outputs = model.generate(**inputs, max_length=50)
    result = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return {"generated_text": result}
"@
$modelScript | Out-File -FilePath "$llmSetupDir\model_inference.py"

# Step 6: Run the LLM server with FastAPI and Uvicorn
Write-Log "Setting up service to run FastAPI with Uvicorn for model inference."

$serviceScript = @"
# Start FastAPI server
cd $llmSetupDir
python -m uvicorn model_inference:app --host 0.0.0.0 --port 8000 --log-level info
"@
$serviceScript | Out-File -FilePath "$llmSetupDir\start_llm_service.ps1"

Write-Log "Service setup script created at $llmSetupDir\start_llm_service.ps1. Run this script to start the LLM inference server."

# Step 7: Create a shortcut to easily start the server
Write-Log "Creating a shortcut on the Desktop to start the LLM service."

$shortcutPath = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "Start LLM Service.lnk")
$shortcut = (New-Object -COM WScript.Shell).CreateShortcut($shortcutPath)
$shortcut.TargetPath = "$llmSetupDir\start_llm_service.ps1"
$shortcut.Save()

Write-Log "Setup complete. LLM service can be started by running the shortcut on your Desktop or executing $llmSetupDir\start_llm_service.ps1"
Write-Output "Setup complete. Review log file at $logFile for details."
