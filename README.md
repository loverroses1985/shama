# Anbar Project - Backend (Express + SQLite)

This project provides:
- An Express backend that serves your existing frontend (place files into `/public`).
- REST API endpoints for authentication (JWT), forms CRUD, and file upload.
- SQLite database (`data.db`) in project root (uses `better-sqlite3`).

## Quick local run
1. Install Node.js (v14+).
2. `npm install`
3. `npm start`
4. Open `http://localhost:3000`

## API summary
- `POST /api/auth/register` { username, password } -> { user, token }
- `POST /api/auth/login` { username, password } -> { user, token }
- `GET /api/forms` (auth) -> list of user's forms
- `POST /api/forms` (auth) { title, data } -> create form
- `GET/PUT/DELETE /api/forms/:id` (auth)
- `POST /api/upload` (auth, form field name 'file') -> upload files

## Deployment notes
- Recommended: Render (web service for backend), Vercel/Netlify for frontend static hosting, or deploy backend+frontend together on Render / Replit.
- Set environment variable `JWT_SECRET` in production.
- Change seeded admin password immediately.