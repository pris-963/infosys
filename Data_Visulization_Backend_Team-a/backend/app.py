import os
from flask import Flask, send_from_directory
from flask_cors import CORS

from routes.events import events_bp
from routes.stats import stats_bp
from routes.threats import threats_bp
from routes.auth import auth_bp
from routes.prediction_routes import prediction_bp
from routes.risk_routes import risk_bp
from routes.incident_routes import incident_bp
from db import get_connection_info


# --------------------------------------------------
# Frontend dist path
# --------------------------------------------------

frontend_dist_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "Data_Visulization_Frontend_Team-a",
        "dist",
    )
)


# --------------------------------------------------
# Flask Application
# --------------------------------------------------

app = Flask(
    __name__,
    static_folder=frontend_dist_dir,
    static_url_path=""
)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "security_project_secret_session_key"
)


# --------------------------------------------------
# CORS Configuration
# --------------------------------------------------

# Local development origins
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
]

# Production frontend URL
frontend_url = os.getenv(
    "FRONTEND_URL",
    "https://infosysproject-mf6p.onrender.com"
).rstrip("/")

if frontend_url and frontend_url not in allowed_origins:
    allowed_origins.append(frontend_url)


CORS(
    app,
    origins=allowed_origins,
    supports_credentials=True,
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Content-Type",
        "Authorization",
    ],
)


# --------------------------------------------------
# Milestone 1 APIs
# --------------------------------------------------

app.register_blueprint(
    events_bp,
    url_prefix="/api"
)

app.register_blueprint(
    stats_bp,
    url_prefix="/api"
)

app.register_blueprint(
    threats_bp,
    url_prefix="/api"
)

app.register_blueprint(
    auth_bp
)

# Direct aliases for development
app.register_blueprint(
    events_bp,
    url_prefix="",
    name="events_root"
)

app.register_blueprint(
    stats_bp,
    url_prefix="",
    name="stats_root"
)

app.register_blueprint(
    threats_bp,
    url_prefix="",
    name="threats_root"
)


# --------------------------------------------------
# Milestone 2 Prediction APIs
# --------------------------------------------------

app.register_blueprint(
    prediction_bp,
    url_prefix="/api"
)


# --------------------------------------------------
# Milestone 3 Risk APIs
# --------------------------------------------------

app.register_blueprint(
    risk_bp,
    url_prefix="/api/v1"
)

app.register_blueprint(
    risk_bp,
    url_prefix="/api",
    name="risk_api"
)


# --------------------------------------------------
# Milestone 3 Incident APIs
# --------------------------------------------------

app.register_blueprint(
    incident_bp,
    url_prefix="/api/v1"
)

app.register_blueprint(
    incident_bp,
    url_prefix="/api",
    name="incident_api"
)


# --------------------------------------------------
# API Health Check
# --------------------------------------------------

@app.route("/api")
def api_health():
    conn = get_connection_info()

    return {
        "Project": (
            "Security Operations Dashboard for Threat Detection "
            "with Risk Mitigation Analytics"
        ),
        "Backend": "Running",
        "Version": "3.0",
        "Database": conn["database"],
        "Connection": conn["source"],
        "Connected": conn["connected"],

        "Milestone_1_2_Endpoints": [
            "GET /api/events",
            "GET /api/events?severity=Critical",
            "GET /api/events?event_type=Brute Force",
            "GET /api/stats",
            "GET /api/threats",
            "GET /api/threats?severity=Critical",
            "GET /api/predictions",
            "GET /api/predictions/<event_id>",
            "GET /api/anomalies",
            "GET /api/model-performance",
            "GET /api/threat-summary",
            "POST /api/predict",
            "POST /api/login",
            "POST /api/signup",
        ],

        "Milestone_3_Endpoints": [
            "GET /api/v1/risk/summary",
            "GET /api/v1/risk/high",
            "GET /api/v1/risk/high?risk_class=Critical",
            "GET /api/v1/risk/high?limit=50&offset=0",
            "POST /api/v1/risk/calculate",
            "GET /api/v1/incidents",
            "GET /api/v1/incidents?priority=Critical",
            "GET /api/v1/incidents?status=Open&limit=50&offset=0",
            "GET /api/v1/incidents/<incident_id>",
            "GET /api/v1/attack-chains",
            "GET /api/v1/attack-chains?min_events=2&limit=50",
            "GET /api/v1/recommendations/<incident_id>",
        ],

        "Docs": "See backend/README.md for full request/response details",
    }


# --------------------------------------------------
# Frontend Catch-All
# --------------------------------------------------

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):

    # Serve requested static frontend file
    if (
        path
        and app.static_folder
        and os.path.exists(
            os.path.join(app.static_folder, path)
        )
    ):
        return send_from_directory(
            app.static_folder,
            path
        )

    # Serve Vite index.html if available
    if (
        app.static_folder
        and os.path.exists(
            os.path.join(
                app.static_folder,
                "index.html"
            )
        )
    ):
        return send_from_directory(
            app.static_folder,
            "index.html"
        )

    # Backend-only fallback
    conn = get_connection_info()

    return {
        "Project": (
            "Security Operations Dashboard for Threat Detection "
            "with Risk Mitigation Analytics"
        ),
        "Backend": "Running",
        "Version": "3.0",
        "Database": conn["database"],
        "Connection": conn["source"],
        "Connected": conn["connected"],
        "Note": (
            "Frontend not built in this backend deployment. "
            "Use the separate Render frontend service."
        ),
    }


# --------------------------------------------------
# Local Development
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        debug=True,
        use_reloader=False,
        host="0.0.0.0",
        port=5000
    )
