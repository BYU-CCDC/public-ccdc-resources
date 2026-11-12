1. **Run the Server**:
   - To start the server, run the `start_llm_service.sh` script:
     ```bash
     bash ~/llm_setup/start_llm_service.sh
     ```

### Accessing the Model API

Once the server is running, you can interact with the model through the API at `http://localhost:8000/generate`. Send a POST request with JSON input, like so:

```json
{
  "input_text": "Hello, how are you?"
}
```

### Notes

- **Model Choice**: This example uses `distilgpt2`, which is lightweight and optimized for CPU usage. Replace `distilgpt2` in `model_inference.py` with another model name if needed.
- **Resource Efficiency**: This setup is designed for CPU and is suitable for small form-factor devices, like single-board computers or mini PCs.
- **Local Development**: This configuration runs locally. If you want it to be accessible remotely, ensure proper firewall and network security.
