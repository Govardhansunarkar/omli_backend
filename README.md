# Backend (formerly z++Security)

This folder contains the Express backend for the project.

Quick start (Windows / PowerShell):

```powershell
cd backend
npm install
npm start
```

Environment variables (backend/.env or environment):
- `MONGO_URI` - MongoDB connection string
- `JWT_SECRET` - JWT signing secret
- `PORT` - optional, defaults to `5000`
- `GOOGLE_CLIENT_ID` - Google OAuth client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth client secret

Notes:
- Keep `backend/.env` out of source control (add to `.gitignore`).
- The frontend expects the backend URL in `NEXT_PUBLIC_API_URL`.
