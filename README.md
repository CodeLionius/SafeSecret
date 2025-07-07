# SafeSecret

A secure, self-destructing secret sharing web app inspired by [umputun/secrets](https://github.com/umputun/secrets).

## Features
- Share confidential information with a one-time, self-destructing link
- PIN-protected access (5-character PIN)
- Secrets are encrypted in memory using Fernet symmetric encryption
- Secrets are destroyed after being read or after expiration
- Modern, mobile-friendly web interface

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
   python app.py
   ```
   The app will be available at [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Usage
- Go to the home page, enter your secret, choose expiration, and set a 5-character PIN.
- Share the generated link with your recipient.
- The recipient must enter the correct PIN to view the secret. The secret is destroyed after being read or after expiration.

## Running Tests

1. Make sure you have `pytest` installed:
   ```bash
   pip install pytest
   ```
2. Run the tests:
   ```bash
   pytest test_app.py
   ```

## Security Notes
- **Encryption:** All secrets are encrypted in memory using a Fernet key. The key must be kept secret and set via the `FERNET_KEY` environment variable.
- **No persistent storage:** Secrets are only stored in memory and are lost if the server restarts.
- **No logging of secrets or PINs.**
- **Always use HTTPS in production.**

## Credits & Inspiration
- Inspired by [umputun/secrets](https://github.com/umputun/secrets)
- Built with Flask, Bootstrap, and cryptography

---

Feel free to contribute or suggest improvements! 