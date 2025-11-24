# EVER Aadhaar eKYC Verification (Render)

Lightweight FastAPI service that decrypts UIDAI Offline e-KYC ZIP using Share Code, parses XML, extracts name & masked Aadhaar, and returns a verification result.

## Deploy on Render
- Push this repo to GitHub.
- Create a new Web Service on Render.
- Set Start Command:
  uvicorn app:app --host 0.0.0.0 --port $PORT
- Add environment variables as needed:
  MATCH_NAME_SCORE=75
  MAX_SHARECODE_ATTEMPTS=5

## Test locally:
uvicorn app:app --reload
