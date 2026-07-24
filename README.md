# Cybervault

#### Video Demo: https://youtu.be/xlq1D_Ijga8?si=sLp4zkh1dz9LBjGc

#### Description:

Cybervault is a secure, web-based password manager built with Flask, SQL, and Python's `cryptography` library, created as my CS50x final project. As a Cybersecurity student and security intern, I wanted my final project to be more than a course exercise — I wanted to build a tool that reflects real security engineering practices: encryption at rest, breach detection, and password hygiene enforcement, all wrapped in a clean, usable web interface.

## What It Does

Cybervault lets a user register an account, log in securely, and store credentials for different websites in a personal, encrypted vault. For each entry the user adds, the application automatically:

1. **Encrypts the password** using symmetric encryption (Fernet, built on AES) before it ever touches the database. Passwords are never stored in plaintext.
2. **Scores password strength** on a 0–4 scale based on length, character variety (uppercase, lowercase, digits, symbols), giving the user immediate feedback on how strong their credential is.
3. **Checks the password against known data breaches** using the Have I Been Pwned API, via the k-anonymity model — only the first 5 characters of the password's SHA-1 hash are ever sent over the network, so the actual password never leaves the user's machine. If a match is found, the entry is flagged as breached.

Users can reveal a stored password on demand (fetched via an authenticated AJAX request and decrypted server-side), and delete entries they no longer need. Every vault is scoped to the logged-in user, so no one can see or access another user's stored credentials.

## Files and What They Contain

- **`app.py`** — the core Flask application. It defines all routes: `/register`, `/login`, `/logout`, `/` (view and add vault entries), `/reveal/<id>` (decrypt and return a password via JSON), and `/delete/<id>`. It also contains the `password_strength()` function (the scoring heuristic) and `check_breach()` function (the Have I Been Pwned integration using the k-anonymity model). A `login_required` decorator protects all vault routes from unauthenticated access, mirroring the pattern used in CS50's Finance problem set.
- **`cybervault.db`** — the SQLite database with two tables: `users` (id, username, hashed password) and `vault` (id, user_id, site, site_username, encrypted_password, strength_score, breached flag, timestamp). Passwords are hashed with Werkzeug's `generate_password_hash` for login credentials, and vault entries are encrypted separately with Fernet.
- **`templates/layout.html`** — the shared base template with navigation and flash message rendering, extended by every other page.
- **`templates/register.html`** and **`templates/login.html`** — simple authentication forms.
- **`templates/index.html`** — the main vault page: a form to add new entries and a table listing all stored entries, with a "Show" button that reveals a password via a fetch request rather than rendering it in plaintext on page load.
- **`static/styles.css`** — a dark, security-tool-themed stylesheet for the whole application.
- **`vault.key`** — the locally generated Fernet encryption key used to encrypt/decrypt vault passwords. (In a production deployment this would be stored in a secrets manager rather than on disk, which I note as a known limitation below.)

## Design Choices

I chose Flask with server-rendered Jinja templates rather than a JavaScript framework because the project's core value is backend security logic (encryption, hashing, breach checking), and I wanted to focus my effort there rather than on frontend tooling. I used the `cs50` SQL library for consistency with the rest of the course, and SQLite for simplicity, though the code would port to Postgres or MySQL with minimal changes.

One deliberate design decision was checking breaches using the k-anonymity range API instead of sending full passwords to a third-party service — this was important to me given my cybersecurity background; a password manager that leaks passwords to check if they've leaked would defeat its own purpose.

## Known Limitations and Future Work

The encryption key is currently stored as a local file for simplicity; a production version would use a proper key management service. I'd also like to add: a "generate strong password" feature, automatic re-checking of stored entries against new breaches, and two-factor authentication at login. These were left out to keep the project scoped appropriately for a solo submission within the course timeline.
