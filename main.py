import requests, random, string
import secrets
import hashlib
import base64

from flask import Flask, render_template, redirect, request, url_for, session
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from helpers import is_access_token_valid, is_id_token_valid, config
from user import User


app = Flask(__name__)
app.config.update({'SECRET_KEY': ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=32))})

login_manager = LoginManager()
login_manager.init_app(app)


APP_STATE = 'ApplicationState'
NONCE = 'SampleNonce'


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login")
def login():

    state, nonce = generate_state_nonce()

    # Generate code verifier and challenge for PKCE
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    # Store state and nonce in the session for later validation
    session['code_verifier'] = code_verifier
    session['oauth_state'] = state
    session['oauth_nonce'] = nonce

    # get request params
    query_params = {'client_id': config["client_id"],
                    'redirect_uri': config["redirect_uri"],
                    'scope': "openid email profile",
                    'state': state,
                    'nonce': nonce,
                    'response_type': 'code',
                    'response_mode': 'query',
                    'prompt': 'login',
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256'
                    }

    # build request_uri
    request_uri = "{base_url}?{query_params}".format(
        base_url=config["auth_uri"],
        query_params=requests.compat.urlencode(query_params)
    )

    return redirect(request_uri)

def generate_state_nonce():
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    return state, nonce

def generate_code_verifier():
    """Generate a secure random code verifier."""
    return secrets.token_urlsafe(32)

def generate_code_challenge(code_verifier):
    """Generate the code challenge based on the code verifier."""
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    # Base64 URL-encode the digest and remove padding
    challenge = base64.urlsafe_b64encode(digest).decode('utf-8').replace("=", "")
    return challenge


@app.route("/profile")
@login_required
def profile():
    print(current_user)
    return render_template("profile.html", user=current_user)


@app.route("/callback")
def callback():
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Retrieve state and nonce from the session
    session_state = session.get('oauth_state')
    session_nonce = session.get('oauth_nonce')

    # Retrieve state from the request parameters
    request_state = request.args.get('state')

    # Compare the state from the request with the one stored in the session
    if not request_state or request_state != session_state:
        return "State parameter mismatch", 403

    # First, check for errors in the request args
    error = request.args.get("error")
    error_description = request.args.get("error_description")
    
    # If there is an error, return a custom message based on the error description
    if error:
        # Replace spaces with plus signs to match the URL-encoded format if needed
        error_message = error_description.replace('+', ' ') if error_description else "Unknown error"
        return f"Error: {error}. Description: {error_message}", 403
    
    
    code = request.args.get("code")
    if not code:
        return "The code was not returned or is not accessible", 403
    
    # Retrieve the code verifier from the session
    code_verifier = session.pop('code_verifier', None)
    if not code_verifier:
        return "Code verifier not found", 400

    query_params = {'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': request.base_url,
                    'code_verifier': code_verifier
                    }
    query_params = requests.compat.urlencode(query_params)
    exchange = requests.post(
        config["token_uri"],
        headers=headers,
        data=query_params,
        auth=(config["client_id"], config["client_secret"]),
    ).json()

    print(exchange)

    # Get tokens and validate
    if not exchange.get("token_type"):
        return "Unsupported token type. Should be 'Bearer'.", 403
    access_token = exchange["access_token"]
    id_token = exchange["id_token"]

    print("Access token", access_token)
    print("/n")
    print(id_token)

    if not is_access_token_valid(access_token, config["issuer"]):
        return "Access token is invalid", 403

    if not is_id_token_valid(id_token, config["issuer"], config["client_id"], nonce=session_nonce):
        return "ID token is invalid", 403

    # Authorization flow successful, get userinfo and login user
    userinfo_response = requests.get(config["userinfo_uri"],
                                     headers={'Authorization': f'Bearer {access_token}'}).json()

    unique_id = userinfo_response["sub"]
    user_email = userinfo_response["email"]
    user_name = userinfo_response["given_name"]

    user = User(
        id_=unique_id, name=user_name, email=user_email
    )

    if not User.get(unique_id):
        User.create(unique_id, user_name, user_email)

    login_user(user)

    return redirect(url_for("profile"))


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("home"))


if __name__ == '__main__':
    app.run(host="localhost", port=8080, debug=True)
