"""Expense Tracker - Flask application.

Configuration is read from environment variables (see .env.example):
    APP_ENV         "production" enables strict settings (default: development)
    SECRET_KEY      required in production
    DATABASE_PATH   path to the SQLite file (default: ./expenses.db)
    APP_TIMEZONE    IANA timezone used for "today" / "this month" (default: Asia/Kolkata)
"""
import csv
import hmac
import io
import logging
import math
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from zoneinfo import ZoneInfo

from flask import (
    Flask, Response, abort, flash, g, redirect, render_template, request,
    session, url_for,
)
from flask_login import (
    LoginManager, UserMixin, current_user, login_required, login_user,
    logout_user,
)
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
IS_PRODUCTION = os.environ.get("APP_ENV", "development").lower() == "production"
DATABASE = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "expenses.db"))
TIMEZONE = os.environ.get("APP_TIMEZONE", "Asia/Kolkata")

CATEGORIES = ["Food", "Travel", "Shopping", "Bills", "Other"]
CATEGORY_COLORS = {  # keep in sync with the .cat-* rules in static/style.css
    "Food": "#e4572e",
    "Travel": "#2a7de1",
    "Shopping": "#8e5bd9",
    "Bills": "#d99a00",
    "Other": "#6b7c85",
}
PAGE_SIZE = 15
MAX_AMOUNT = Decimal("10000000")  # 1 crore, guards against typos
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60

app = Flask(__name__)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    if IS_PRODUCTION:
        raise RuntimeError("SECRET_KEY must be set when APP_ENV=production")
    secret_key = secrets.token_hex(32)  # dev only: sessions reset on restart

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,  # requires HTTPS in production
    PERMANENT_SESSION_LIFETIME=timedelta(days=14),
    MAX_CONTENT_LENGTH=64 * 1024,
)
logging.basicConfig(level=logging.INFO)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "info"
login_manager.session_protection = "strong"


# --------------------------------------------------------------------------
# Time helpers (the original used SQLite DATE('now'), which is UTC)
# --------------------------------------------------------------------------
def local_now():
    try:
        return datetime.now(ZoneInfo(TIMEZONE))
    except Exception:  # unknown timezone or missing tzdata
        return datetime.now()


def month_start(d):
    return d.replace(day=1)


def next_month_start(d):
    return (d.replace(day=1) + timedelta(days=32)).replace(day=1)


def prev_month_start(d):
    return (d.replace(day=1) - timedelta(days=1)).replace(day=1)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and apply lightweight migrations. Safe to run repeatedly."""
    db = sqlite3.connect(DATABASE, timeout=10)
    try:
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                monthly_budget REAL NOT NULL DEFAULT 0
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                amount REAL NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                date TEXT NOT NULL
            )
        """)
        # Migrations for databases created by the earlier version
        expense_cols = [r[1] for r in db.execute("PRAGMA table_info(expenses)")]
        if "user_id" not in expense_cols:
            db.execute("ALTER TABLE expenses ADD COLUMN user_id INTEGER")
        user_cols = [r[1] for r in db.execute("PRAGMA table_info(users)")]
        if "monthly_budget" not in user_cols:
            db.execute(
                "ALTER TABLE users ADD COLUMN monthly_budget REAL NOT NULL DEFAULT 0"
            )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_expenses_user_date "
            "ON expenses (user_id, date)"
        )
        db.commit()
    finally:
        db.close()


init_db()  # runs under gunicorn too, not only `python app.py`


# --------------------------------------------------------------------------
# Users / auth
# --------------------------------------------------------------------------
class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.email = row["email"]
        self.monthly_budget = float(row["monthly_budget"] or 0)


@login_manager.user_loader
def load_user(user_id):
    row = get_db().execute(
        "SELECT id, username, email, monthly_budget FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    return User(row) if row else None


DUMMY_HASH = generate_password_hash("not-a-real-password")  # evens out login timing
_failed_logins = {}


def too_many_attempts(key):
    now = time.time()
    recent = [t for t in _failed_logins.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    _failed_logins[key] = recent
    return len(recent) >= LOGIN_MAX_FAILURES


def record_failure(key):
    if len(_failed_logins) > 5000:  # keep memory bounded
        _failed_logins.clear()
    _failed_logins.setdefault(key, []).append(time.time())


def is_safe_next(target):
    return bool(
        target and target.startswith("/")
        and not target.startswith("//") and "\\" not in target
    )


# --------------------------------------------------------------------------
# CSRF protection and security headers
# --------------------------------------------------------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_from_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "").encode()
        expected = session.get("_csrf", "").encode()
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, description="Your session expired. Reload the page and try again.")


@app.after_request
def set_security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    )
    if IS_PRODUCTION:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    if current_user.is_authenticated:
        resp.headers["Cache-Control"] = "no-store"  # don't cache private pages
    return resp


# --------------------------------------------------------------------------
# Template helpers
# --------------------------------------------------------------------------
@app.template_filter("inr")
def inr(value):
    """Format as rupees with Indian digit grouping: 1234567.5 -> ₹12,34,567.50"""
    try:
        value = float(value or 0)
    except (TypeError, ValueError):
        value = 0.0
    sign = "-" if value < 0 else ""
    whole, frac = f"{abs(value):.2f}".split(".")
    if len(whole) > 3:
        head, tail = whole[:-3], whole[-3:]
        groups = []
        while len(head) > 2:
            groups.insert(0, head[-2:])
            head = head[:-2]
        if head:
            groups.insert(0, head)
        whole = ",".join(groups + [tail])
    return f"{sign}₹{whole}.{frac}"


@app.template_filter("pretty_date")
def pretty_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").strftime("%d %b %Y")
    except (TypeError, ValueError):
        return value or ""


@app.template_filter("cat_class")
def cat_class(category):
    return "cat-" + (category.lower() if category in CATEGORIES else "other")


@app.context_processor
def inject_globals():
    return {"CATEGORIES": CATEGORIES, "today": local_now().date().isoformat()}


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
def parse_money(raw, allow_zero=False):
    """Return (Decimal, None) or (None, error message)."""
    try:
        value = Decimal(raw.strip())
    except (InvalidOperation, AttributeError):
        return None, "Enter a valid amount."
    if not value.is_finite():
        return None, "Enter a valid amount."
    value = value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if value < 0 or (value == 0 and not allow_zero):
        return None, "Amount must be greater than 0."
    if value > MAX_AMOUNT:
        return None, f"Amount cannot be more than {inr(MAX_AMOUNT)}."
    return value, None


def valid_date(raw):
    try:
        datetime.strptime(raw or "", "%Y-%m-%d")
        return raw
    except ValueError:
        return ""


def parse_expense(form):
    """Validate an add/edit form. Returns (clean_values, errors)."""
    errors = []
    amount, err = parse_money(form.get("amount", ""))
    if err:
        errors.append(err)
    category = form.get("category", "").strip()
    if category not in CATEGORIES:
        errors.append("Choose a category.")
    description = form.get("description", "").strip()
    if len(description) > 200:
        errors.append("Description must be 200 characters or less.")
    date = form.get("date", "").strip()
    if not valid_date(date):
        errors.append("Enter a valid date.")
    return {
        "amount": amount, "category": category,
        "description": description, "date": date,
    }, errors


# --------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------

def looks_like_email(value):
    local, _, domain = value.partition("@")
    return bool(local) and "." in domain and " " not in value and len(value) <= 100


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = {"username": "", "email": ""}
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")  # never strip passwords
        form.update(username=username, email=email)

        errors = []
        if not (3 <= len(username) <= 30) or not all(
            c.isalnum() or c in "_.-" for c in username
        ):
            errors.append(
                "Username must be 3 to 30 characters: letters, numbers, _ . or -"
            )
        if not looks_like_email(email):
            errors.append("Enter a valid email address.")
        if not (8 <= len(password) <= 128):
            errors.append("Password must be 8 to 128 characters.")

        db = get_db()
        if not errors:
            taken = db.execute(
                "SELECT username, email FROM users "
                "WHERE lower(username) = ? OR lower(email) = ?",
                (username.lower(), email),
            ).fetchone()
            if taken:
                if taken["username"].lower() == username.lower():
                    errors.append("That username is already taken.")
                if taken["email"].lower() == email:
                    errors.append("An account with that email already exists.")
        if not errors:
            try:
                db.execute(
                    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:  # lost a race with another signup
                errors.append("That username or email is already registered.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", form=form), 400
        flash("Account created. Sign in to continue.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = {"email": ""}
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        form["email"] = email
        if not email or not password:
            flash("Enter your email and password.", "error")
            return render_template("login.html", form=form), 400
        key = (request.remote_addr, email)
        if too_many_attempts(key):
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return render_template("login.html", form=form), 429
        row = get_db().execute(
            "SELECT id, username, email, monthly_budget, password "
            "FROM users WHERE lower(email) = ?",
            (email,),
        ).fetchone()
        password_ok = check_password_hash(row["password"] if row else DUMMY_HASH, password)
        if not row or not password_ok:
            record_failure(key)
            flash("Incorrect email or password.", "error")
            return render_template("login.html", form=form), 401
        _failed_logins.pop(key, None)
        session.pop("_csrf", None)  # fresh token after authentication
        login_user(User(row))
        target = request.args.get("next")
        return redirect(target if is_safe_next(target) else url_for("home"))
    return render_template("login.html", form=form)


@app.post("/logout")
@login_required
def logout():
    logout_user()
    session.pop("_csrf", None)
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
def escape_like(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def parse_filters(args):
    category = args.get("category", "").strip()
    return {
        "search": args.get("search", "").strip()[:100],
        "category": category if category in CATEGORIES else "",
        "date_from": valid_date(args.get("date_from", "").strip()),
        "date_to": valid_date(args.get("date_to", "").strip()),
    }


def build_where(user_id, f):
    clauses, params = ["user_id = ?"], [user_id]
    if f["search"]:
        like = f"%{escape_like(f['search'])}%"
        clauses.append("(description LIKE ? ESCAPE '\\' OR category LIKE ? ESCAPE '\\')")
        params += [like, like]
    if f["category"]:
        clauses.append("category = ?")
        params.append(f["category"])
    if f["date_from"]:
        clauses.append("date >= ?")
        params.append(f["date_from"])
    if f["date_to"]:
        clauses.append("date <= ?")
        params.append(f["date_to"])
    return " AND ".join(clauses), params


def scalar(db, sql, params):
    return db.execute(sql, params).fetchone()[0] or 0


def dashboard_stats(db, user):
    uid = user.id
    today = local_now().date()
    first, nxt = month_start(today), next_month_start(today)
    days_in_month = (nxt - first).days

    all_total, all_count = db.execute(
        "SELECT COALESCE(SUM(amount), 0), COUNT(*) FROM expenses WHERE user_id = ?",
        (uid,),
    ).fetchone()
    today_total = scalar(
        db, "SELECT SUM(amount) FROM expenses WHERE user_id = ? AND date = ?",
        (uid, today.isoformat()),
    )
    range_sql = (
        "SELECT SUM(amount) FROM expenses WHERE user_id = ? AND date >= ? AND date < ?"
    )
    month_total = scalar(db, range_sql, (uid, first.isoformat(), nxt.isoformat()))

    # Like-for-like: last month up to the same day number as today
    prev_first = prev_month_start(today)
    prev_days = (first - prev_first).days
    prev_cut = prev_first + timedelta(days=min(today.day, prev_days))
    prev_total = scalar(db, range_sql, (uid, prev_first.isoformat(), prev_cut.isoformat()))
    delta = None
    if prev_total > 0:
        pct = (month_total - prev_total) / prev_total * 100
        delta = {
            "pct": round(abs(pct), 1),
            "dir": "flat" if round(pct, 1) == 0 else ("up" if pct > 0 else "down"),
        }

    cat_rows = db.execute(
        "SELECT category, SUM(amount) AS total, COUNT(*) AS n FROM expenses "
        "WHERE user_id = ? AND date >= ? AND date < ? "
        "GROUP BY category ORDER BY total DESC",
        (uid, first.isoformat(), nxt.isoformat()),
    ).fetchall()
    categories = [
        {
            "name": r["category"], "total": r["total"], "count": r["n"],
            "share": round(r["total"] / month_total * 100, 1) if month_total else 0,
            "color": CATEGORY_COLORS.get(r["category"], CATEGORY_COLORS["Other"]),
        }
        for r in cat_rows
    ]

    months = []
    m = first
    for _ in range(6):
        months.append(m)
        m = prev_month_start(m)
    months.reverse()
    trend_rows = db.execute(
        "SELECT substr(date, 1, 7) AS ym, SUM(amount) AS total FROM expenses "
        "WHERE user_id = ? AND date >= ? AND date < ? GROUP BY ym",
        (uid, months[0].isoformat(), nxt.isoformat()),
    ).fetchall()
    by_month = {r["ym"]: r["total"] for r in trend_rows}
    trend = {
        "labels": [d.strftime("%b %y") for d in months],
        "values": [round(by_month.get(d.strftime("%Y-%m"), 0), 2) for d in months],
    }

    budget = user.monthly_budget
    budget_pct = month_total / budget * 100 if budget > 0 else 0
    return {
        "month_label": today.strftime("%B"),
        "month_total": month_total,
        "all_total": all_total,
        "all_count": all_count,
        "today_total": today_total,
        "daily_avg": month_total / today.day,
        "projected": month_total / today.day * days_in_month if month_total else 0,
        "delta": delta,
        "categories": categories,
        "top_category": categories[0] if categories else None,
        "budget": budget,
        "budget_pct": round(budget_pct, 1),
        "budget_bar": min(100, round(budget_pct, 1)),
        "budget_state": "over" if budget_pct >= 100 else ("warn" if budget_pct >= 80 else "ok"),
        "budget_left": budget - month_total,
        "chart": {
            "trend": trend,
            "categories": {
                "labels": [c["name"] for c in categories],
                "values": [round(c["total"], 2) for c in categories],
                "colors": [c["color"] for c in categories],
            },
        },
        "today_date": today,
    }


@app.route("/")
@login_required
def home():
    db = get_db()
    f = parse_filters(request.args)
    where, params = build_where(current_user.id, f)

    count, filtered_total = db.execute(
        f"SELECT COUNT(*), COALESCE(SUM(amount), 0) FROM expenses WHERE {where}", params
    ).fetchone()
    pages = max(1, math.ceil(count / PAGE_SIZE))
    page = min(max(request.args.get("page", 1, type=int), 1), pages)
    expenses = db.execute(
        f"SELECT id, amount, category, description, date FROM expenses WHERE {where} "
        "ORDER BY date DESC, id DESC LIMIT ? OFFSET ?",
        params + [PAGE_SIZE, (page - 1) * PAGE_SIZE],
    ).fetchall()

    stats = dashboard_stats(db, current_user)
    today = stats["today_date"]
    keep = {k: v for k, v in f.items() if v and k in ("search", "category")}
    month_from = month_start(today).isoformat()
    last30_from = (today - timedelta(days=29)).isoformat()
    only_dates = lambda d: f["date_from"] == d and not f["date_to"]  # noqa: E731
    presets = [
        {"label": "All time", "args": keep,
         "active": not f["date_from"] and not f["date_to"]},
        {"label": "This month", "args": {**keep, "date_from": month_from},
         "active": only_dates(month_from)},
        {"label": "Last 30 days", "args": {**keep, "date_from": last30_from},
         "active": only_dates(last30_from)},
    ]
    filter_args = {k: v for k, v in f.items() if v}
    return render_template(
        "index.html", expenses=expenses, filters=f, filter_args=filter_args,
        filters_active=bool(filter_args), presets=presets,
        count=count, filtered_total=filtered_total,
        page=page, pages=pages, **stats,
    )


@app.get("/export")
@login_required
def export_csv():
    f = parse_filters(request.args)
    where, params = build_where(current_user.id, f)
    rows = get_db().execute(
        f"SELECT date, category, description, amount FROM expenses WHERE {where} "
        "ORDER BY date DESC, id DESC",
        params,
    ).fetchall()

    def safe(text):  # neutralise spreadsheet formula injection
        text = text or ""
        return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Date", "Category", "Description", "Amount (INR)"])
    for r in rows:
        writer.writerow([r["date"], r["category"], safe(r["description"]), f"{r['amount']:.2f}"])
    name = f"expenses-{local_now().date().isoformat()}.csv"
    return Response(
        out.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@app.post("/budget")
@login_required
def set_budget():
    amount, err = parse_money(request.form.get("monthly_budget", ""), allow_zero=True)
    if err:
        flash(err, "error")
    else:
        db = get_db()
        db.execute("UPDATE users SET monthly_budget = ? WHERE id = ?",
                   (float(amount), current_user.id))
        db.commit()
        flash("Monthly budget saved." if amount > 0 else "Monthly budget removed.", "success")
    return redirect(url_for("home"))


# --------------------------------------------------------------------------
# Expense CRUD
# --------------------------------------------------------------------------
@app.route("/add", methods=["GET", "POST"])
@login_required
def add_expense():
    form = {"amount": "", "category": "", "description": "",
            "date": local_now().date().isoformat()}
    if request.method == "POST":
        clean, errors = parse_expense(request.form)
        form = {k: request.form.get(k, "").strip() for k in form}
        if errors:
            return render_template("add_expense.html", form=form, errors=errors), 400
        db = get_db()
        db.execute(
            "INSERT INTO expenses (user_id, amount, category, description, date) "
            "VALUES (?, ?, ?, ?, ?)",
            (current_user.id, float(clean["amount"]), clean["category"],
             clean["description"], clean["date"]),
        )
        db.commit()
        flash("Expense added.", "success")
        return redirect(url_for("home"))
    return render_template("add_expense.html", form=form, errors=[])


@app.route("/edit/<int:expense_id>", methods=["GET", "POST"])
@login_required
def edit_expense(expense_id):
    db = get_db()
    row = db.execute(
        "SELECT id, amount, category, description, date FROM expenses "
        "WHERE id = ? AND user_id = ?",
        (expense_id, current_user.id),
    ).fetchone()
    if row is None:
        abort(404, description="That expense doesn't exist or isn't yours.")

    if request.method == "POST":
        clean, errors = parse_expense(request.form)
        form = {k: request.form.get(k, "").strip()
                for k in ("amount", "category", "description", "date")}
        if errors:
            return render_template("edit_expense.html", expense=row, form=form,
                                   errors=errors), 400
        db.execute(
            "UPDATE expenses SET amount = ?, category = ?, description = ?, date = ? "
            "WHERE id = ? AND user_id = ?",
            (float(clean["amount"]), clean["category"], clean["description"],
             clean["date"], expense_id, current_user.id),
        )
        db.commit()
        flash("Expense updated.", "success")
        return redirect(url_for("home"))

    form = {"amount": f"{row['amount']:.2f}", "category": row["category"],
            "description": row["description"] or "", "date": row["date"]}
    return render_template("edit_expense.html", expense=row, form=form, errors=[])


@app.post("/delete/<int:expense_id>")
@login_required
def delete_expense(expense_id):
    db = get_db()
    cur = db.execute("DELETE FROM expenses WHERE id = ? AND user_id = ?",
                     (expense_id, current_user.id))
    db.commit()
    flash("Expense deleted." if cur.rowcount else "That expense no longer exists.",
          "success" if cur.rowcount else "info")
    return redirect(request.referrer if request.referrer and
                    request.referrer.startswith(request.host_url) else url_for("home"))


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------
ERROR_TITLES = {
    400: "Something went wrong with that request",
    404: "Page not found",
    405: "That action isn't allowed here",
    413: "That request was too large",
    429: "Too many requests",
    500: "Something went wrong on our side",
}


def handle_error(err):
    code = getattr(err, "code", 500) or 500
    if code >= 500:
        app.logger.exception("Unhandled error", exc_info=err)
    message = getattr(err, "description", "") if code < 500 else (
        "We've logged the problem. Please try again in a moment.")
    return render_template("error.html", code=code,
                           title=ERROR_TITLES.get(code, "Error"),
                           message=message), code


for _code in ERROR_TITLES:
    app.register_error_handler(_code, handle_error)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
