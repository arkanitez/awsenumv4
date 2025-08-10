# AWS Enum — Modern UI

Minimal inputs, modern UI.

- **Only two inputs**: Access Key ID, Secret Access Key
- **One button**: Enumerate
- **Default region**: `ap-southeast-1`

## Run
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS:
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000
```
