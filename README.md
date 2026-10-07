# Expense Tracker

Flask + SQLite expense tracker with a mobile-first UI, monthly budget and a spending dashboard.

## Run locally

```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py                                         # http://127.0.0.1:5000
```

Set `FLASK_DEBUG=1` only on your own machine if you want auto-reload. Never in production.

## Deploy checklist

1. Set environment variables (see `.env.example`):
   - `APP_ENV=production` (the app refuses to start without `SECRET_KEY` in this mode)
   - `SECRET_KEY`: generate with `python -c "import secrets; print(secrets.token_hex(32))"`
   - `DATABASE_PATH`: a path on persistent storage, for example `/var/data/expenses.db`
   - `APP_TIMEZONE`: defaults to `Asia/Kolkata`; controls what "today" and "this month" mean
2. Serve over **HTTPS** (session cookies are marked `Secure` in production).
3. Start with a production server, not `python app.py`:
   ```bash
   gunicorn -w 3 -b 0.0.0.0:8000 app:app
   ```
4. Back up the SQLite file regularly (it runs in WAL mode, so copy `expenses.db` together with `expenses.db-wal` or use `sqlite3 expenses.db ".backup backup.db"`).

## Upgrading an existing database

The app migrates automatically on startup (adds `user_id`, `monthly_budget` and an index).
Expenses created before logins existed have no owner, so nobody can see them. To give them to a user:

```sql
UPDATE expenses SET user_id = 1 WHERE user_id IS NULL;   -- 1 = that user's id
```
