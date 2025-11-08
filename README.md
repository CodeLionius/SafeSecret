# SafeSecret
A secure, self-destructing secret and file sharing web app inspired by [umputun/secrets](https://github.com/umputun/secrets).

## Features
- Share confidential text or files with a one-time, self-destructing link
- PIN-protected access (5-character PIN)
- Secrets and files are encrypted in memory using Fernet symmetric encryption
- **Files and secrets are securely deleted from memory after being read or after expiration**
- Modern, mobile-friendly, and accessible web interface
- Clear expiry and usage feedback for recipients
- No files or secrets are ever written to disk by default (RAM-only storage)
- "Back to Home" navigation and improved copy-to-clipboard feedback

## Production Deployment

The app can be deployed to any standard Python environment. For a live demo, see:

👉 [https://safesecret-1.onrender.com](https://safesecret-1.onrender.com)

## Setup & Installation

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd <your-project-folder>
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Generate a Fernet key** (for encryption)
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
   Copy the output and set it as an environment variable:
   ```bash
   export FERNET_KEY='your-generated-key'
   ```

4. **(Optional) Set Flask environment to production**
   ```bash
   export FLASK_ENV=production
   ```

5. **Run the app**
   ```bash
   python3 app.py
   ```
   The app will be available at [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Usage
- Go to the home page, enter your secret and/or upload files, choose expiration, and set a 5-character PIN.
- Share the generated link with your recipient.
- The recipient must enter the correct PIN to view or download the secret/files.
- **Secrets and files are destroyed after being read once or after expiration, whichever comes first.**
- All file data is securely overwritten in memory before deletion for maximum privacy.

## Running Tests

1. Make sure you have `pytest` installed:
   ```bash
   pip install pytest
   ```
2. Run the backend tests:
   ```bash
   pytest test_app.py
   ```
3. (Optional) Run UI tests with Playwright:
   ```bash
   pytest test_ui_playwright.py
   ```

## Security Notes
- **Encryption:** All secrets and files are encrypted in memory using a Fernet key. The key must be kept secret and set via the `FERNET_KEY` environment variable.
- **No persistent storage:** By default, secrets and files are only stored in memory and are lost if the server restarts.
- **No logging of secrets or PINs.**
- **Always use HTTPS in production.**
- **Files are securely deleted from memory after use or expiry.**

## Housekeeping
- Unused HTML and screenshot files in the project root can be deleted if not needed for documentation or testing.
- All actual templates are in the `templates/` directory.

## Credits & Inspiration
- Built with Flask, Bootstrap, and cryptography

---

Feel free to contribute or suggest improvements! 