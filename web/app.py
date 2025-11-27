from flask import Flask
from web.routes import blueprint as ui_routes
from web.api import blueprint as api_routes

def create_app():
    app = Flask(__name__)

    # Registramos las rutas
    app.register_blueprint(ui_routes)
    app.register_blueprint(api_routes, url_prefix="/api")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)