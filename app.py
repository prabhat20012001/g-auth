import os
import pathlib

import requests
from flask import Flask, session, abort, redirect, request, render_template_string
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

app = Flask("Google Login App")
app.secret_key = "CodeSpecialist.com"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "749463331207-r0r75tm6lad3ucntnalhcvq9it30m6bf.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials

    # Fetch user information
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["profile_picture"] = id_info.get("picture")

    # Store the user's email address in the session
    session["email"] = id_info.get("email")

    return redirect("/protected_area")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/")
def index():
    return "Hello World <br><a href='/login'><button>Login</button></a>"


@app.route("/protected_area")
@login_is_required
def protected_area():
    username = session['name']
    profile_picture = session.get('profile_picture')
    email = session.get('email')  # Retrieve the user's email from the session

    # HTML template to display the user's profile picture, username, and email
    html_template = f"Hello {username}!<br/>"
    if profile_picture:
        html_template += f"<img src='{profile_picture}' alt='Profile Picture'><br/>"

    if email:
        html_template += f"Email: {email}<br/>"

    html_template += "<a href='/logout'><button>Logout</button></a>"

    return render_template_string(html_template)


if __name__ == "__main__":
    app.run(debug=True)
