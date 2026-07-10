from shred.routes import admin, files, pages


def register_blueprints(app):
    app.register_blueprint(pages.bp)
    app.register_blueprint(files.bp)
    app.register_blueprint(admin.bp)
