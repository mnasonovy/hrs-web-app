import math
import os
import subprocess
from datetime import datetime

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, url_for

load_dotenv()

app = Flask(__name__)

SEVERITIES = ["низкая", "средняя", "высокая", "критическая"]
STATUSES = ["открыт", "в работе", "закрыт"]
CATEGORIES = [
    "Аутентификация",
    "Сетевые атаки",
    "WEB-угрозы",
    "База данных",
    "DMZ",
    "NGFW",
    "Fail2Ban",
    "Мониторинг",
]


@app.template_filter("slug")
def slug_filter(value):
    return str(value).lower().replace(" ", "_")


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


def get_stats():
    row = fetch_one(
        """
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'открыт') AS open_count,
            COUNT(*) FILTER (WHERE status = 'в работе') AS investigating_count,
            COUNT(*) FILTER (WHERE status = 'закрыт') AS closed_count,
            COUNT(*) FILTER (WHERE severity IN ('высокая', 'критическая')) AS high_critical_count,
            COUNT(*) FILTER (WHERE severity = 'критическая') AS critical_count
        FROM incidents;
        """
    )

    return row or {
        "total": 0,
        "open_count": 0,
        "investigating_count": 0,
        "closed_count": 0,
        "high_critical_count": 0,
        "critical_count": 0,
    }


def get_db_status():
    try:
        row = fetch_one("SELECT 1 AS result;")
        if row and row["result"] == 1:
            return "ONLINE", None
        return "ERROR", "PostgreSQL не вернул ожидаемый ответ."
    except Exception as exc:
        return "ERROR", str(exc)


def get_ngfw_status():
    ngfw_host = os.getenv("NGFW_CHECK_HOST", "10.10.10.1")

    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ngfw_host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )

        if result.returncode == 0:
            return "ONLINE", ngfw_host

        return "UNREACHABLE", ngfw_host

    except Exception:
        return "ERROR", ngfw_host


def build_incident_filters():
    selected_status = request.args.get("status", "all")
    selected_severity = request.args.get("severity", "all")
    selected_category = request.args.get("category", "all")
    search_query = request.args.get("q", "").strip()

    filters = []
    params = []

    if selected_status != "all":
        filters.append("status = %s")
        params.append(selected_status)

    if selected_severity != "all":
        filters.append("severity = %s")
        params.append(selected_severity)

    if selected_category != "all":
        filters.append("category = %s")
        params.append(selected_category)

    if search_query:
        filters.append(
            """
            (
                title ILIKE %s
                OR source_ip ILIKE %s
                OR assignee ILIKE %s
                OR asset ILIKE %s
                OR description ILIKE %s
            )
            """
        )
        like_query = f"%{search_query}%"
        params.extend([like_query, like_query, like_query, like_query, like_query])

    where_clause = ""
    if filters:
        where_clause = "WHERE " + " AND ".join(filters)

    return {
        "where_clause": where_clause,
        "params": params,
        "selected_status": selected_status,
        "selected_severity": selected_severity,
        "selected_category": selected_category,
        "search_query": search_query,
    }


def get_context(active_page):
    db_status, error_message = get_db_status()
    ngfw_status, ngfw_host = get_ngfw_status()

    return {
        "active_page": active_page,
        "db_status": db_status,
        "error_message": error_message,
        "ngfw_status": ngfw_status,
        "ngfw_host": ngfw_host,
        "current_year": datetime.now().year,
        "severities": SEVERITIES,
        "statuses": STATUSES,
        "categories": CATEGORIES,
    }


@app.route("/")
def dashboard():
    context = get_context("dashboard")
    stats = get_stats()

    recent_incidents = fetch_all(
        """
        SELECT
            id,
            title,
            severity,
            status,
            category,
            source_ip,
            asset,
            assignee,
            created_at,
            updated_at
        FROM incidents
        ORDER BY created_at DESC, id DESC
        LIMIT 8;
        """
    )

    critical_incidents = fetch_all(
        """
        SELECT
            id,
            title,
            severity,
            status,
            asset,
            source_ip,
            created_at
        FROM incidents
        WHERE severity = 'критическая' AND status != 'закрыт'
        ORDER BY created_at DESC, id DESC
        LIMIT 5;
        """
    )

    context.update(
        {
            "stats": stats,
            "recent_incidents": recent_incidents,
            "critical_incidents": critical_incidents,
        }
    )

    return render_template("dashboard.html", **context)


@app.route("/incidents")
def incidents():
    context = get_context("incidents")
    filter_data = build_incident_filters()

    page = request.args.get("page", "1")
    try:
        page = int(page)
    except ValueError:
        page = 1

    if page < 1:
        page = 1

    per_page = 10
    offset = (page - 1) * per_page

    count_row = fetch_one(
        f"""
        SELECT COUNT(*) AS total
        FROM incidents
        {filter_data["where_clause"]};
        """,
        tuple(filter_data["params"]),
    )

    total = count_row["total"] if count_row else 0
    total_pages = max(1, math.ceil(total / per_page))

    if page > total_pages:
        page = total_pages
        offset = (page - 1) * per_page

    query_params = list(filter_data["params"])
    query_params.extend([per_page, offset])

    incident_rows = fetch_all(
        f"""
        SELECT
            id,
            title,
            severity,
            status,
            category,
            source_ip,
            asset,
            assignee,
            description,
            recommendation,
            created_at,
            updated_at
        FROM incidents
        {filter_data["where_clause"]}
        ORDER BY
            CASE severity
                WHEN 'критическая' THEN 1
                WHEN 'высокая' THEN 2
                WHEN 'средняя' THEN 3
                WHEN 'низкая' THEN 4
                ELSE 5
            END,
            created_at DESC,
            id DESC
        LIMIT %s OFFSET %s;
        """,
        tuple(query_params),
    )

    context.update(
        {
            "incidents": incident_rows,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "selected_status": filter_data["selected_status"],
            "selected_severity": filter_data["selected_severity"],
            "selected_category": filter_data["selected_category"],
            "search_query": filter_data["search_query"],
        }
    )

    return render_template("incidents.html", **context)


@app.route("/incident/<int:incident_id>")
def incident_detail(incident_id):
    context = get_context("incidents")

    incident = fetch_one(
        """
        SELECT
            id,
            title,
            severity,
            status,
            category,
            source_ip,
            asset,
            assignee,
            description,
            recommendation,
            created_at,
            updated_at
        FROM incidents
        WHERE id = %s;
        """,
        (incident_id,),
    )

    if not incident:
        return redirect(url_for("incidents"))

    context.update({"incident": incident})
    return render_template("incident_detail.html", **context)


@app.route("/incidents/add", methods=["POST"])
def add_incident():
    title = request.form.get("title", "").strip()
    severity = request.form.get("severity", "средняя").strip()
    status = request.form.get("status", "открыт").strip()
    category = request.form.get("category", "Мониторинг").strip()
    source_ip = request.form.get("source_ip", "").strip()
    asset = request.form.get("asset", "HRS-WEB").strip()
    assignee = request.form.get("assignee", "HRS SOC").strip()
    description = request.form.get("description", "").strip()
    recommendation = request.form.get("recommendation", "").strip()

    if severity not in SEVERITIES:
        severity = "средняя"

    if status not in STATUSES:
        status = "открыт"

    if category not in CATEGORIES:
        category = "Мониторинг"

    if title:
        execute_query(
            """
            INSERT INTO incidents (
                title,
                severity,
                status,
                category,
                source_ip,
                asset,
                assignee,
                description,
                recommendation,
                updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP);
            """,
            (
                title,
                severity,
                status,
                category,
                source_ip or None,
                asset or "HRS-WEB",
                assignee or "HRS SOC",
                description or "Инцидент создан вручную оператором HRS SOC.",
                recommendation or "Проверить журналы, сетевые правила и связанные сервисы.",
            ),
        )

    return redirect(url_for("incidents"))


@app.route("/incident/<int:incident_id>/update", methods=["POST"])
def update_incident(incident_id):
    title = request.form.get("title", "").strip()
    severity = request.form.get("severity", "средняя").strip()
    status = request.form.get("status", "открыт").strip()
    category = request.form.get("category", "Мониторинг").strip()
    source_ip = request.form.get("source_ip", "").strip()
    asset = request.form.get("asset", "HRS-WEB").strip()
    assignee = request.form.get("assignee", "HRS SOC").strip()
    description = request.form.get("description", "").strip()
    recommendation = request.form.get("recommendation", "").strip()

    if severity not in SEVERITIES:
        severity = "средняя"

    if status not in STATUSES:
        status = "открыт"

    if category not in CATEGORIES:
        category = "Мониторинг"

    if title:
        execute_query(
            """
            UPDATE incidents
            SET
                title = %s,
                severity = %s,
                status = %s,
                category = %s,
                source_ip = %s,
                asset = %s,
                assignee = %s,
                description = %s,
                recommendation = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s;
            """,
            (
                title,
                severity,
                status,
                category,
                source_ip or None,
                asset or "HRS-WEB",
                assignee or "HRS SOC",
                description,
                recommendation,
                incident_id,
            ),
        )

    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incident/<int:incident_id>/delete", methods=["POST"])
def delete_incident(incident_id):
    execute_query(
        """
        DELETE FROM incidents
        WHERE id = %s;
        """,
        (incident_id,),
    )

    return redirect(url_for("incidents"))


@app.route("/incident/<int:incident_id>/action/<action>", methods=["POST"])
def incident_action(incident_id, action):
    if action == "close":
        execute_query(
            """
            UPDATE incidents
            SET status = 'закрыт', updated_at = CURRENT_TIMESTAMP
            WHERE id = %s;
            """,
            (incident_id,),
        )

    elif action == "reopen":
        execute_query(
            """
            UPDATE incidents
            SET status = 'открыт', updated_at = CURRENT_TIMESTAMP
            WHERE id = %s;
            """,
            (incident_id,),
        )

    elif action == "investigate":
        execute_query(
            """
            UPDATE incidents
            SET status = 'в работе', updated_at = CURRENT_TIMESTAMP
            WHERE id = %s;
            """,
            (incident_id,),
        )

    elif action == "escalate":
        execute_query(
            """
            UPDATE incidents
            SET
                status = 'в работе',
                severity = 'критическая',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s;
            """,
            (incident_id,),
        )

    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/analytics")
def analytics():
    context = get_context("analytics")
    stats = get_stats()

    severity_stats = fetch_all(
        """
        SELECT severity, COUNT(*) AS count
        FROM incidents
        GROUP BY severity
        ORDER BY
            CASE severity
                WHEN 'критическая' THEN 1
                WHEN 'высокая' THEN 2
                WHEN 'средняя' THEN 3
                WHEN 'низкая' THEN 4
                ELSE 5
            END;
        """
    )

    status_stats = fetch_all(
        """
        SELECT status, COUNT(*) AS count
        FROM incidents
        GROUP BY status
        ORDER BY count DESC;
        """
    )

    category_stats = fetch_all(
        """
        SELECT category, COUNT(*) AS count
        FROM incidents
        GROUP BY category
        ORDER BY count DESC;
        """
    )

    top_assets = fetch_all(
        """
        SELECT asset, COUNT(*) AS count
        FROM incidents
        GROUP BY asset
        ORDER BY count DESC
        LIMIT 7;
        """
    )

    context.update(
        {
            "stats": stats,
            "severity_stats": severity_stats,
            "status_stats": status_stats,
            "category_stats": category_stats,
            "top_assets": top_assets,
        }
    )

    return render_template("analytics.html", **context)


@app.route("/architecture")
def architecture():
    context = get_context("architecture")
    return render_template("architecture.html", **context)


@app.route("/health")
def health():
    try:
        row = fetch_one("SELECT 1 AS result;")
        if row and row["result"] == 1:
            return {
                "status": "ok",
                "database": "ok",
                "service": "HRS SOC Command Center",
            }

        return {"status": "error", "database": "error"}, 500

    except Exception as exc:
        return {
            "status": "error",
            "database": "error",
            "message": str(exc),
        }, 500


if __name__ == "__main__":
    host = os.getenv("APP_HOST", "127.0.0.1")
    port = int(os.getenv("APP_PORT", "8000"))

    app.run(host=host, port=port)
