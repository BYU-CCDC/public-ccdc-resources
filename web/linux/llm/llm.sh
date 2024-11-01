#!/bin/bash

# Define variables
LLM_SETUP_DIR="$HOME/llm_setup"
MODEL_DIR="$LLM_SETUP_DIR/model"
LOG_FILE="$LLM_SETUP_DIR/setup_log.txt"
MODEL_NAME="distilgpt2"  # Lightweight model for CPU
PYTHON_VERSION="3.9"

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "Starting small form factor LLM setup..."

# Step 1: Create a directory for LLM setup
if [ ! -d "$LLM_SETUP_DIR" ]; then
    mkdir -p "$LLM_SETUP_DIR"
    log "Created directory for LLM setup at $LLM_SETUP_DIR."
fi

# Step 2: Install Python if not already installed
if ! command -v python3 &> /dev/null; then
    log "Python not found. Installing Python $PYTHON_VERSION..."
    sudo apt update
    sudo apt install -y python${PYTHON_VERSION} python3-pip
    log "Python installed."
else
    log "Python is already installed."
fi

# Step 3: Upgrade pip and install necessary Python packages
log "Upgrading pip and installing required Python packages..."
python3 -m pip install --upgrade pip
python3 -m pip install torch transformers fastapi uvicorn pydantic

# Step 4: Set up a small language model (e.g., DistilGPT2)
log "Downloading and setting up a lightweight LLM for CPU..."
if [ ! -d "$MODEL_DIR" ]; then
    mkdir -p "$MODEL_DIR"
fi

# Step 5: Write the FastAPI server script for model inference
log "Creating model inference script using FastAPI..."
cat <<EOF > "$LLM_SETUP_DIR/model_inference.py"
from fastapi import FastAPI, Request
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

app = FastAPI()

# Load lightweight model
model_name = '${MODEL_NAME}'
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
EOF

# Step 6: Create a script to run the FastAPI server with Uvicorn
log "Creating script to start FastAPI server with Uvicorn..."
cat <<EOF > "$LLM_SETUP_DIR/start_llm_service.sh"
#!/bin/bash
# Start FastAPI server for model inference
cd "$LLM_SETUP_DIR"
python3 -m uvicorn model_inference:app --host 0.0.0.0 --port 8000 --log-level info
EOF

chmod +x "$LLM_SETUP_DIR/start_llm_service.sh"

log "Setup complete. You can start the LLM inference server by running: $LLM_SETUP_DIR/start_llm_service.sh"
log "Service is configured to run on http://localhost:8000/generate."
