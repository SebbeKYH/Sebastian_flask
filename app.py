# This makes environment specific content available through version handling.
import dotenv
# Import flask application that can be used as a server object
from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

# Initializing SQLAlchemy which handles interaction with database
db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    # Many parts of flask will require use to use a secret key so we create one
    app.config['SECRET_KEY'] = 'UWillNeverKnowMySecret'
    # Turn off SqlAlchemy warning
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Will configure SQLAlchemy to use SQLite and the file db.sqlite
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

    # Init the SQLAlchemy object with our app object
    db.init_app(app)

    # Create a login manager for flask-login
    login_manager = LoginManager()

    # Init the login manager with our app object
    login_manager.init_app(app)

    # Create a user_loader function. Used by flask-login
    @login_manager.user_loader
    # Takes argument of user_id that comes from relationship table.
    def load_user(user_id):
        #Imports the user-class from models...
        from models import User
        #returns
        return User.query.filter_by(id=user_id).first()

    # Register the open blueprint with the app object
    from blueprints.open import bp_open
    app.register_blueprint(bp_open)

    # Register the user blueprint with the app object
    from blueprints.user import bp_user
    app.register_blueprint(bp_user)

    from blueprints.admin import bp_admin
    app.register_blueprint(bp_admin)

    from blueprints.ajax import bp_ajax
    app.register_blueprint(bp_ajax)

    return app


if __name__ == '__main__':
    dotenv.load_dotenv()
    app = create_app()
    app.run()



