"""Python Flask WebApp Auth0 integration example
"""

import json
import datetime
import logging                             # ← import logging
from os import environ as env
from urllib.parse import quote_plus, urlencode
from functools import wraps

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request

# ─── Load .env ────────────────────────────────────────────────────────────────
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

# ─── Flask + Auth0 setup ──────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

# ─── Ensure INFO-level logs show up ───────────────────────────────────────────
app.logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)
# ──────────────────────────────────────────────────────────────────────────────

oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# ─── Authn decorator ─────────────────────────────────────────────────────────
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            app.logger.warning({
                "event": "UNAUTHORIZED",
                "path":  request.path,
                "time":  datetime.datetime.utcnow().isoformat() + "Z"
            })
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ─── Routes ─────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    userinfo = token.get("userinfo", {})

    # ─── Structured LOGIN log ────────────────────────────────────────────────
    app.logger.info({
        "event":   "LOGIN",
        "user_id": userinfo.get("sub"),
        "email":   userinfo.get("email"),
        "time":    datetime.datetime.utcnow().isoformat() + "Z"
    })

    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        f"https://{env.get('AUTH0_DOMAIN')}/v2/logout?"
        + urlencode(
            {"returnTo": url_for("home", _external=True),
             "client_id": env.get("AUTH0_CLIENT_ID")},
            quote_via=quote_plus,
        )
    )

@app.route("/protected")
@requires_auth
def protected():
    # Pull the userinfo dict out of the stored token
    userinfo = session["user"]["userinfo"]

    # ─── Structured PROTECTED_HIT log ───────────────────────────────────────
    app.logger.info({
        "event":   "PROTECTED_HIT",
        "user_id": userinfo.get("sub"),
        "route":   "/protected",
        "time":    datetime.datetime.utcnow().isoformat() + "Z"
    })

    # Simple HTML response; you can swap this out for a template
    return (
        "<h1>🔒 Protected Page</h1>"
        f"<p>Welcome, {userinfo.get('name')}!</p>"
        "<p><a href='/logout'>Logout</a></p>"
    )

# ─── Run ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(env.get("PORT", 3000)))
