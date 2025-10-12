### Running the Script

1. **Run the Script**:
   - Execute the script in an elevated PowerShell prompt to set up everything.

2. **Start the LLM Server**:
   - Once the setup is complete, double-click the **"Start LLM Service"** shortcut on your desktop or manually run `start_llm_service.ps1` in PowerShell. This will start the FastAPI server.

3. **Access the Model API**:
   - The server will be accessible at `http://localhost:8000/generate`. You can send a POST request with JSON input to generate text:
     ```json
     {
       "input_text": "Hello, how are you?"
     }
     ```

### Notes

- **Model Choice**: This script uses `distilgpt2` as an example. You can replace `distilgpt2` with any small model that fits your requirements, such as `MiniLM`.
- **Resource Efficiency**: The setup is optimized for CPUs, making it suitable for small form-factor systems. However, larger models may be slow on CPUs.
- **Custom Configurations**: Modify `max_length` or other model parameters in `model_inference.py` to adjust response length or behavior.

