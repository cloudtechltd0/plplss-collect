# PalPluss Collect

`backend/` FastAPI API -> Render. `frontend/` static dashboard -> Vercel.

## 1. Backend on Render
1. Push this repo to GitHub.
2. Render -> New -> Blueprint -> pick the repo (it reads `render.yaml`; creates the web service + free Postgres).
3. Fill the prompted env vars: `PALPLUSS_API_KEY`, `ADMIN_PASSWORD`, `FRONTEND_ORIGIN` (your Vercel URL, no trailing slash), `CALLBACK_URL`.
4. `CALLBACK_URL` = `https://<your-service>.onrender.com/api/palpluss/callback?token=<CALLBACK_TOKEN>` (copy the generated `CALLBACK_TOKEN` from Render's env tab).
5. Check `https://<your-service>.onrender.com/api/health`.

## 2. Frontend on Vercel
1. Edit `frontend/config.js` and set `API_BASE` to your Render URL.
2. Vercel -> Add New Project -> import the repo -> set **Root Directory** to `frontend`, Framework **Other**, no build command.
3. Deploy, then put the Vercel URL into `FRONTEND_ORIGIN` on Render (comma-separate multiple origins).

## Notes
- Render free web services sleep after idle; the first login can take ~30s. Use a paid plan or a cron ping to `/api/health` to avoid it.
- Render free Postgres expires after a period; upgrade for production data.
- Local dev: `cd backend && pip install -r requirements.txt && uvicorn main:app --reload`, then serve `frontend/` (e.g. `python -m http.server 5500`) with `API_BASE` set to `http://localhost:8000`.
