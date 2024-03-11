# Flask + Okta Hosted Login Example

This example shows you how to use Flask to log in to your application with an Okta Hosted Login page.  The login is achieved through the [authorization code flow](https://developer.okta.com/authentication-guide/implementing-authentication/auth-code), where the user is redirected to the Okta-Hosted login page.  After the user authenticates, they are redirected back to the application with an access code that is then exchanged for an access token.

> Requires Python version 3.6.0 or higher.

## Running This Example

To run this application, you first need to clone this repo:

```bash
git clone git@github.com:okta/samples-python-flask.git
cd samples-python-flask
```

Then install dependencies:

```bash
python3 -m venv <project-name>
source <project-name>/bin/activate
pip install -r requirements.txt
```

Fill in the information that you gathered in the `client_secrets.json` file.

```json
{
  "auth_uri": "https://{yourOktaDomain}/oauth2/default/v1/authorize",
  "client_id": "{yourClientId}",
  "client_secret": "{yourClientSecret}",
  "redirect_uri": "http://localhost:8080/authorization-code/callback",
  "issuer": "https://{yourOktaDomain}/oauth2/default",
  "token_uri": "https://{yourOktaDomain}/oauth2/default/v1/token",
  "token_introspection_uri": "https://{yourOktaDomain}/oauth2/default/v1/introspect",
  "userinfo_uri": "https://{yourOktaDomain}/oauth2/default/v1/userinfo"
}
```

Start the app server:

```
python main.py
```

Now navigate to http://localhost:8080 in your browser.
