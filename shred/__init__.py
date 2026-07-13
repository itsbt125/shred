import logging

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from shred import config
from shred.cleanup import start_cleanup_thread
from shred.db import close_db, ensure_admin_token, init_db
from shred.routes import register_blueprints

__version__ = "1.0.0"

_bootstrapped = False


class _StripServerHeader:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def _start_response(status, headers, *args):
            headers = [(k, v) for k, v in headers if k.lower() != "server"]
            return start_response(status, headers, *args)
        return self.app(environ, _start_response)


def _add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive, nosnippet"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    # Deliberately no COEP: require-corp — it broke the service-worker streaming download in Firefox.
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def _no_cache_api(response):
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


def _handle_413(e):
    return jsonify({"error": "file too large"}), 413


def _handle_404(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "not found"}), 404
    return render_template("expired.html"), 404


def _handle_500(e):
    return jsonify({"error": "internal error"}), 500


def create_app(bootstrap=True):
    global _bootstrapped

    app = Flask(
        __name__,
        template_folder=str(config.TEMPLATES_DIR),
        static_folder=str(config.STATIC_DIR),
    )
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_CHUNK_BYTES

    logging.getLogger("shred").setLevel(logging.ERROR)

    if config.TRUSTED_PROXY_COUNT > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=config.TRUSTED_PROXY_COUNT,
            x_proto=config.TRUSTED_PROXY_COUNT,
        )
    else:
        # print(), not logging: the "shred" logger is pinned to ERROR above and would swallow this.
        print(
            "[shred] WARNING TRUSTED_PROXY_COUNT=0: using the direct peer as the "
            "client IP. If a reverse proxy sits in front of shred, set "
            "TRUSTED_PROXY_COUNT to the number of proxies, or per-IP rate limiting "
            "and IP allowlisting will not work correctly.",
            flush=True,
        )

    app.wsgi_app = _StripServerHeader(app.wsgi_app)

    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    app.teardown_appcontext(close_db)
    app.after_request(_add_security_headers)
    app.after_request(_no_cache_api)

    app.register_error_handler(RequestEntityTooLarge, _handle_413)
    app.register_error_handler(404, _handle_404)
    app.register_error_handler(500, _handle_500)

    register_blueprints(app)

    if bootstrap and not _bootstrapped:
        _bootstrapped = True
        init_db()
        ensure_admin_token()
        start_cleanup_thread()

    return app


app = create_app()
