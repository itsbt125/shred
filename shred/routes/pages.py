import json

from flask import Blueprint, jsonify, render_template

from shred import config
from shred.storage import valid_id

bp = Blueprint("pages", __name__)


def _embed_config():
    # Embedded verbatim in a <script type="application/json"> block via |safe,
    # so escape the one sequence that could break out of that element: "</"
    # (as in "</script>"). Escaping "<" to its JSON unicode form is enough and
    # keeps the payload valid JSON. Only operator-set values (expiry labels)
    # can reach here and the CSP already blocks inline script execution, but
    # this closes the breakout regardless. json.dumps defaults to
    # ensure_ascii=True, which already escapes U+2028/U+2029.
    return json.dumps(config.client_config()).replace("<", "\\u003c")


@bp.route("/api/config")
def api_config():
    return jsonify(config.client_config())


@bp.route("/")
def index():
    return render_template(
        "index.html",
        upload_token_required=config.token_gating_enabled(),
        max_file_size_display=config.format_bytes(config.MAX_FILE_SIZE),
        expiry_options=config.EXPIRY_OPTIONS,
        config_json=_embed_config(),
    )


@bp.route("/expired")
def expired():
    return render_template("expired.html")


@bp.route("/f/<file_id>")
def view_file(file_id):
    if not valid_id(file_id):
        return render_template("expired.html"), 404
    return render_template("view.html", config_json=_embed_config())


@bp.route("/admin")
def admin_page():
    return render_template("admin.html")


@bp.route("/status")
def status_page():
    return render_template("status.html")


@bp.route("/terms")
def terms_page():
    days = config.MAX_EXPIRY_SECONDS // 86400
    max_expiry_display = f"{days} days" if days > 1 else f"{days} day"
    return render_template(
        "terms.html",
        abuse_contact=config.ABUSE_CONTACT,
        max_expiry_display=max_expiry_display,
    )
