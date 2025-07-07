
# 25S_CST8919_Assignment_1
## Securing &amp; Monitoring an Authenticated Flask App

**Student:** Daniel Abou-Assaly  

**Student ID:** 041173113

**Professor:** Ramy Mohamed  

[Watch on YouTube](https://youtu.be/fxj5rsPvci0)


---
## Step 1: Auth0 Account Setup

1. **Sign up** for an Auth0 account via GitHub  
   - Go to [Auth0](https://auth0.com/) and click **Sign Up**  
   - Choose **Sign up with GitHub**

2. **Select** the **Developer** (free) plan

3. **Create a new application**  
   - Navigate to **Applications → Create Application**  
   - **Type:** **Regular Web Application**  

4. **Choose** your technology  
   - Select the **Python** card  

5. **Skip** optional settings (logo, social connections, colors)

6. **Enable** the built-in Database connection  
   - Make sure **Enabled** is checked  
   - **Create a test user** (you’ll use this later):
   ```text
   Email:    demo_user@example.com  
   Password: Password123!
   ```
---
## Step 2: Download Sample App & Configure Auth0 Credentials

1. **Download & extract** the sample app  
   - Click **Download Sample App**  
   - Extract the ZIP into `25S_CST8919_Lab_1` on your Desktop  
   - Inside it, you’ll see the `01-login` folder  

2. **Configure Callback & Logout URLs**  
   - In Auth0 Dashboard → **Applications** → **[Your App]** → **Settings**  
   - **Allowed Callback URLs**: (`(http://localhost:3000/callback, http://127.0.0.1:3000/callback, http://myflaskapppppdan-fjgreghnbvgubcgu.eastus2-01.azurewebsites.net/callback)`)  
   - **Allowed Logout URLs**:   (`(http://localhost:3000/callback, http://127.0.0.1:3000/callback, http://myflaskapppppdan-fjgreghnbvgubcgu.eastus2-01.azurewebsites.net/)`)  
   - Click **Save Changes**  

3. **Open PowerShell** and navigate to your project folder  
   ```powershell
   cd C:\Users\dan\Desktop\25S_CST8919_Lab_1\01-login
   ```
4. **Copy Your Auth0 Credentials**
   - From the Auth0 Dashboard → **Applications** → **[Your App]** → **Settings**, copy:
   - **Domain:**  
     `dev-ixlhmtd0gcgsdsnr.us.auth0.com`
   - **Client ID:**  
     `XzOJvNEwbXjv97uhfwaco....`
   - **Client Secret:**  
     `Z5uvYp_MfMMUFSWsZ1w31j03zmCcd4xkLIR8ViKqfPX9KaG7i.....`
     
5. Edit Your **Environment File**
   - Open `01-login/.env` in VS Code, Notepad++, or your editor of choice.  
   - Replace the placeholders so the file reads:

   ```dotenv
   AUTH0_CLIENT_ID=XzOJvNEwbXjv97uhfwac....
   AUTH0_CLIENT_SECRET=Z5uvYp_MfMMUFSWsZ1w31j03zmCcd4xkLIR8ViKqfPX.....
   AUTH0_DOMAIN=dev-ixlhmtd0gcgsdsnr.us.auth0.com
   APP_SECRET_KEY=ALongRandomlyGeneratedString
   ```
---
## Step 3: Create & Activate a Virtual Environment
1. go back to the **root folder**
   ```powershell
   cd C:\Users\dan\Desktop\25S_CST8919_Lab_1
   ```
2. Create the **venv**
   ```powershell
   py -3 -m venv venv
   ```
3. Activate the **venv**
   - enable first script execution
   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```
   - Then activate
   ```powershell
   & .\venv\Scripts\Activate.ps1
   ```
---
## Step 4: Install Dependencies
- Go back to the **01-login** folder
```powershell
cd C:\Users\dan\Desktop\25S_CST8919_Lab_1\01-login
```
- install
```powershell
pip install -r requirements.txt
```
---
## Azure Resources

### Resource Group

| Name           | Type           | Region   | Notes                         |
| -------------- | -------------- | -------- | ----------------------------- |
| `Assignment1RG` | Resource Group | East US 2 | Parent for all other resources |

### App Service Plan

| Name                     | Type                | Region   | SKU       | Notes                             |
| ------------------------ | ------------------- | -------- | --------- | --------------------------------- |
| `ASP-Assignment1RG-<id>` | App Service Plan    | East US 2 | Free F1 / B1 | Hosts the Flask web app |

### Web App

| Name                        | Type    | Region   | Runtime       | URL                                                                                   |
| --------------------------- | ------- | -------- | ------------- | ------------------------------------------------------------------------------------- |
| `myflaskapppppdan`          | Web App | East US 2 | Python 3.11   | https://myflaskapppppdan-fjgreghnbvgubcgu.eastus2-01.azurewebsites.net                 |

### Log Analytics Workspace

| Name             | Type                     | Region   | Workspace ID                                   |
| ---------------- | ------------------------ | -------- | ---------------------------------------------- |
| `Assignment1LAW` | Log Analytics workspace  | East US 2 | 805ef5cd-dba2-4928-a666-50cf5f429a0d            |

### Diagnostic Settings

| Resource           | Logs Enabled              | Destination Workspace | Notes                      |
| ------------------ | ------------------------- | --------------------- | -------------------------- |
| `myflaskapppppdan` | App Service Console Logs<br>App Service Application Logs | `Assignment1LAW`      | Streams structured app.logger output |

### Alerting

| Name                 | Type               | Target Scope     | Condition                                               | Frequency | Threshold | Action Group            |
| -------------------- | ------------------ | ---------------- | ------------------------------------------------------- | --------- | --------- | ----------------------- |
| `ExcessProtectedHits` | Log alert (v2)     | `Assignment1LAW` | >10 “PROTECTED_HIT” events by any user in a 15 min window | 5 min     | 10 rows   | `ExcessProtectedHits` AG |

### Action Group

| Name                   | Type      | Notification Method | Recipient Email                |
| ---------------------- | --------- | ------------------- | ------------------------------ |
| `ExcessProtectedHits`  | Action Group | Email               | your.email@domain.com          |
## Logging & Detection Logic

### Logging

- **Structured application logs**  
  In `app.py` we emit three structured JSON log events via Flask’s `app.logger`:
  1. **LOGIN**  
     ```python
     app.logger.info({
       "event":   "LOGIN",
       "user_id": userinfo.get("sub"),
       "email":   userinfo.get("email"),
       "time":    datetime.datetime.utcnow().isoformat() + "Z"
     })
     ```
  2. **PROTECTED_HIT**  
     ```python
     app.logger.info({
       "event":   "PROTECTED_HIT",
       "user_id": userinfo.get("sub"),
       "route":   "/protected",
       "time":    datetime.datetime.utcnow().isoformat() + "Z"
     })
     ```
  3. **UNAUTHORIZED**  
     ```python
     app.logger.warning({
       "event":    "UNAUTHORIZED",
       "path":     request.path,
       "time":     datetime.datetime.utcnow().isoformat() + "Z"
     })
     ```
- **Azure App Service configuration**  
  - **Application Logging (Filesystem)** turned **On** at **Information** level  
  - **Diagnostic setting** streams both **Console Logs** and **Application Logs** into our Log Analytics workspace (`Assignment1LAW`)  

### Detection Logic

We want to catch any user who hits the protected endpoint more than 10 times in a rolling 15-minute window. To do that:

1. **Query** the `AppServiceConsoleLogs` table in Log Analytics.  
2. **Filter** to only our `PROTECTED_HIT` events.  
3. **Parse** each log’s JSON payload.  
4. **Count** the hits per `user_id` in 15-minute bins.  
5. **Alert** if any count exceeds 10.

---

## KQL Query & Alert Logic

```kql
// 1. Start from the diagnostic logs table
AppServiceConsoleLogs
// 2. Narrow to our structured PROTECTED_HIT entries
| where ResultDescription contains "PROTECTED_HIT"
// 3. Parse the JSON payload
| extend payload = todynamic(ResultDescription)
// 4. Count hits per user in 15-minute windows
| summarize count_hits = count()
    by user_id = tostring(payload.user_id),
       window = bin(TimeGenerated, 15m)
// 5. Only keep windows where the count > 10
| where count_hits > 10
```
## app.py
```python
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

```
## Reflection

Overall this assignment gave me a chance to bring together identity, observability, and alerting in a cohesive DevSecOps workflow.  

**What worked well**  
- **Auth0 SSO integration**: I was able to reuse and extend my Lab 1 Flask/Auth0 code without issues.  
- **Structured logging**: All three events (`LOGIN`, `PROTECTED_HIT`, `UNAUTHORIZED`) were emitted as JSON via `app.logger.info()` and `.warning()` and surfaced in both local console and Azure App Service logs.  
- **Azure deployment & diagnostics**:  
  - I successfully deployed the app to a Linux App Service (Python 3.11)  
  - Enabled Application Logging (Filesystem) and Diagnostic Settings to stream `AppServiceConsoleLogs` into my Log Analytics workspace  
- **KQL detection**: My query accurately counted `/protected` hits per user in 15-minute bins and filtered for counts > 10.  
- **Alert rule**: The `ExcessProtectedHits` rule triggered correctly when forced via “Run query” and was visible under Monitor → Alerts.  

**What I’d improve**  
- **Email notifications**: I hit a hiccup getting the real alert email to fire end-to-end. Although my Action Group test emails succeeded, the live alert didn’t send automatically on schedule. I suspect the evaluation schedule or rule scope needs fine-tuning.  
- **Faster alert frequency**: Azure’s “Aggregated logs” alerts have a minimum 5 min evaluation period. For real-time security monitoring, a 1 min cadence or a metric-based alert might be preferable.  
- **Documentation & scripts**: I’d add a small wrapper script to automate the “11 rapid `/protected` hits” test, and integrate that into CI to validate alert functionality on every deployment.

Despite the email trigger quirk, I was able to demonstrate secure SSO, structured logging, KQL-based detection, and alerting logic end-to-end—even if the final notification needs a bit more polish.

