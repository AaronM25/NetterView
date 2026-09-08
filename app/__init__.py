# app/__init__.py

import os
from flask import Flask, render_template
from flask_cors import CORS
from . import models

def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Configure allowed CORS origins via env var (comma separated), default to localhost UI
    allowed = os.environ.get("ALLOWED_ORIGINS", "http://localhost:5000")
    origins = [o.strip() for o in allowed.split(",") if o.strip()]
    CORS(app, resources={r"/api/*": {"origins": origins}})

    # Require database initialization to succeed or crash startup
    models.init_db()

    # Register API blueprint
    from .routes import api
    app.register_blueprint(api)

    # Serve the UI
    @app.route("/")
    def index():
        return render_template("index.html")

    return app


















