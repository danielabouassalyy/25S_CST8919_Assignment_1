# 25S_CST8919_Assignment_1
## Securing &amp; Monitoring an Authenticated Flask App

**Student:** Daniel Abou-Assaly  

**Student ID:** 041173113

**Professor:** Ramy Mohamed  

[Watch on YouTube](https://youtu.be/vQRvKqkR76c)


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
   - **Allowed Callback URLs**: (`[http://localhost:3000/callback](http://localhost:3000/callback, http://127.0.0.1:3000/callback, http://myflaskapppppdan-fjgreghnbvgubcgu.eastus2-01.azurewebsites.net/callback)`)  
   - **Allowed Logout URLs**:   (`[http://localhost:3000](http://localhost:3000/callback, http://127.0.0.1:3000/callback, http://myflaskapppppdan-fjgreghnbvgubcgu.eastus2-01.azurewebsites.net/)`)  
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
     `XzOJvNEwbXjv97uhfwacohH4rBnlpd9x`
   - **Client Secret:**  
     `Z5uvYp_MfMMUFSWsZ1w31j03zmCcd4xkLIR8ViKqfPX9KaG7i86gvLJj9Yhm_apo`
     
5. Edit Your **Environment File**
   - Open `01-login/.env` in VS Code, Notepad++, or your editor of choice.  
   - Replace the placeholders so the file reads:

   ```dotenv
   AUTH0_CLIENT_ID=XzOJvNEwbXjv97uhfwacohH4rBnlpd9x
   AUTH0_CLIENT_SECRET=Z5uvYp_MfMMUFSWsZ1w31j03zmCcd4xkLIR8ViKqfPX9KaG7i86gvLJj9Yhm_apo
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
