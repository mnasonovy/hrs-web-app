import os
from datetime import datetime

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, url_for

load_dotenv()

app = Flask(__name__)


SEVERITIES = ["low", "medium", "high", "critical"]
STATUSES = ["open", "investigating", "closed"]


def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "hrs_database"),
        user=os.getenv("DB_USER", "hrs_web_user"),
        password=os.getenv("DB_PASSWORD", "qwerty!"),
        cursor_factory=RealDictCursor,
    )


def fetch_one(query, params=None):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, params or ())
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row


def fetch_all(query, params=None):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, params or ())
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def execute_query(query, params=None):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, params or ())
    conn.commit()
    cur.close()
    conn.close()


@app.route("/", methods=["GET", "POST"])
def index():
    db_status = "OK"
    error_message = None
    incidents = []
    stats = {
        "total": 0,
        "open": 0,
        "investigating": 0,
        "closed": 0,
        "high_critical": 0,
    }

    selected_status = request.args.get("status", "all")
    selected_severity = request.args.get("severity", "all")
    search_query = request.args.get("q", "").strip()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        severity = request.form.get("severity", "medium").strip()
        status = request.form.get("status", "open").strip()
        source_ip = request.form.get("source_ip", "").strip()
        assignee = request.form.get("assignee", "HRS SOC").strip()

        if severity not in SEVERITIES:
            severity = "medium"

        if status not in STATUSES:
            status = "open"

        if title:
            try:
                execute_query(
                    """
                    INSERT INTO incidents
                    (title, severity, status, source_ip, assignee, updated_at)
                    VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    """,
                    (title, severity, status, source_ip or None, assignee or "HRS SOC"),
                )
            except Exception as exc:
                db_status = "ERROR"
                error_message = str(exc)

        return redirect(url_for("index"))

    try:
        stats_row = fetch_one(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'open') AS open,
                COUNT(*) FILTER (WHERE status = 'investigating') AS investigating,
                COUNT(*) FILTER (WHERE status = 'closed') AS closed,
                COUNT(*) FILTER (WHERE severity IN ('high', 'critical')) AS high_critical
            FROM incidents;
            """
        )

        if stats_row:
            stats = dict(stats_row)

        filters = []
        params = []

        if selected_status != "all":
            filters.append("status = %s")
            params.append(selected_status)

        if selected_severity != "all":
            filters.append("severity = %s")
            params.append(selected_severity)

        if search_query:
            filters.append("(title ILIKE %s OR source_ip ILIKE %s OR assignee ILIKE %s)")
            like_query = f"%{search_query}%"
            params.extend([like_query, like_query, like_query])

        where_clause = ""
        if filters:
            where_clause = "WHERE " + " AND ".join(filters)

        incidents = fetch_all(
            f"""
            SELECT
                id,
                title,
                severity,
                status,
                source_ip,
                assignee,
                created_at,
                updated_at
            FROM incidents
            {where_clause}
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                created_at DESC,
                id DESC;
            """,
            tuple(params),
        )

    except Exception as exc:
        db_status = "ERROR"
        error_message = str(exc)

    return render_template(
        "index.html",
        db_status=db_status,
        error_message=error_message,
        incidents=incidents,
        stats=stats,
        severities=SEVERITIES,
        statuses=STATUSES,
        selected_status=selected_status,
        selected_severity=selected_severity,
        search_query=search_query,
        current_year=datetime.now().year,
    )


@app.route("/incident/<int:incident_id>/update", methods=["POST"])
def update_incident(incident_id):
    title = request.form.get("title", "").strip()
    severity = request.form.get("severity", "medium").strip()
    status = request.form.get("status", "open").strip()
    source_ip = request.form.get("source_ip", "").strip()
    assignee = request.form.get("assignee", "HRS SOC").strip()

    if severity not in SEVERITIES:
        severity = "medium"

    if status not in STATUSES:
        status = "open"

    if title:
        execute_query(
            """
            UPDATE incidents
            SET
                title = %s,
                severity = %s,
                status = %s,
                source_ip = %s,
                assignee = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (
                title,
                severity,
                status,
                source_ip or None,
                assignee or "HRS SOC",
                incident_id,
            ),
        )

    return redirect(url_for("index"))


@app.route("/incident/<int:incident_id>/delete", methods=["POST"])
def delete_incident(incident_id):
    execute_query(
        """
        DELETE FROM incidents
        WHERE id = %s
        """,
        (incident_id,),
    )

    return redirect(url_for("index"))


@app.route("/incident/<int:incident_id>/action/<action>", methods=["POST"])
def incident_action(incident_id, action):
    if action == "close":
        new_status = "closed"
        new_severity = None
    elif action == "reopen":
        new_status = "open"
        new_severity = None
    elif action == "investigate":
        new_status = "investigating"
        new_severity = None
    elif action == "escalate":
        new_status = "investigating"
        new_severity = "critical"
    else:
        return redirect(url_for("index"))

    if new_severity:
        execute_query(
            """
            UPDATE incidents
            SET status = %s, severity = %s, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (new_status, new_severity, incident_id),
        )
    else:
        execute_query(
            """
            UPDATE incidents
            SET status = %s, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (new_status, incident_id),
        )

    return redirect(url_for("index"))


@app.route("/health")
def health():
    try:
        row = fetch_one("SELECT 1 AS result;")
        if row and row["result"] == 1:
            return {"status": "ok", "database": "ok"}
        return {"status": "error", "database": "error"}, 500

    except Exception as exc:
        return {
            "status": "error",
            "database": "error",
            "message": str(exc)
        }, 500


if __name__ == "__main__":
    host = os.getenv("APP_HOST", "127.0.0.1")
    port = int(os.getenv("APP_PORT", "8000"))

    app.run(host=host, port=port)
