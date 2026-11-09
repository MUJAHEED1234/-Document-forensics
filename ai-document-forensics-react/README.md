# FORENSICAI React frontend

## Requirements

- Node.js 18 or newer
- The FastAPI backend from the project root

## Start the frontend

From this directory:

```powershell
npm install
npm run dev
```

By default, the browser uses the same host as the frontend and calls `/api`; the Vite development server proxies these requests to `http://127.0.0.1:8000`. This supports access through a LAN IP while keeping the local backend bound to loopback. Set `FORENSAI_BACKEND_URL` before starting Vite to proxy to another backend. For a separately hosted frontend/API, set `VITE_API_BASE_URL` in `.env` to the reachable API URL and configure the API's CORS allowlist.

## Investigation flow

1. Select up to 10 PDF, JPG, JPEG, or PNG files (15 MB each) and upload them.
2. Choose **Investigate document set** to create a cross-document dossier, or run the single-document modules against the first uploaded file.
3. Review field conflicts, evidence text, page references, and highlighted PDF font-size screening regions.
4. Download the multi-document dossier PDF or the original single-document report.

The backend API documentation is available at `http://127.0.0.1:8000/docs`. All findings are preliminary review indicators and do not establish authenticity or fraud.
