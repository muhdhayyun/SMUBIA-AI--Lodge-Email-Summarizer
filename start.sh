#!/bin/bash
# Start both processes in background
python app.py &

# Run uvicorn (keep it in foreground so container stays alive)
uvicorn web.server:app --host 0.0.0.0 --port 8000