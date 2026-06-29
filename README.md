# HerLens AI — Deepfake & Explicit Content Detection Platform

HerLens is a Flask web application that analyzes uploaded images for explicit content and AI-generated (deepfake) manipulation. It generates encrypted PDF reports, emails the unlock password to the user, and attaches a cryptographic timestamp so reports can be verified later.

**Tagline:** *Her Face. Her Identity. No One's Weapon!*

---

## Features

- **Explicit content detection** using [NudeNet](https://github.com/notAI-tech/NudeNet)
- **Deepfake / AI-generated face analysis** using **OpenCV YuNet** + artifact heuristics (no TensorFlow required)
- **Optional DeepFace anti-spoofing** when TensorFlow is available
- **Risk scoring** with confidence-based thresholds (SAFE → CRITICAL RISK)
- **Encrypted PDF reports** with per-report passwords sent by email
- **Cryptographic timestamps** (SHA-256 hash + HMAC signature) for report verification
- **Analysis history & stats** (admin-protected)
- **Security hardening** — secrets in `.env`, signed PDF downloads, upload validation

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Flask, Flask-SQLAlchemy |
| Database | SQLite |
| ML / CV | NudeNet, OpenCV YuNet, DeepFace (optional), TensorFlow (optional) |
| Reports | ReportLab, PyPDF2 |
| Email | Gmail SMTP |
| Config | python-dotenv |

---

## Prerequisites

- **Python 3.10–3.12** recommended (TensorFlow/DeepFace optional; OpenCV detection works on newer Python too)
- **Gmail account** with an [App Password](https://myaccount.google.com/apppasswords) for sending report emails
- Windows, macOS, or Linux

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/srinidhis1605/HerLens-AI-Deepfake-Detection-Platform.git
cd HerLens-AI-Deepfake-Detection-Platform
```

### 2. Create a virtual environment

**Windows (PowerShell):**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> **Note:** Deepfake detection works out of the box via **OpenCV YuNet** (included in `opencv-python`). DeepFace/TensorFlow is optional — if it fails to load, OpenCV-based detection still runs.

### 4. Configure environment variables

```bash
copy .env.example .env    # Windows
# cp .env.example .env    # macOS / Linux
```

Edit `.env` with your values:

| Variable | Description |
|----------|-------------|
| `FLASK_SECRET_KEY` | Random string for Flask sessions |
| `FLASK_DEBUG` | `true` for local dev, `false` for production |
| `FLASK_PORT` | Port to run on (default: `5000`) |
| `TIMESTAMP_SECRET` | Key used to sign cryptographic timestamps |
| `APP_BASE_URL` | Public URL of your app (e.g. `http://127.0.0.1:5000`) |
| `SENDER_EMAIL` | Gmail address used to send PDF passwords |
| `SENDER_PASSWORD` | Gmail App Password (16 characters, no spaces) |
| `TESTING_MODE` | `true` = log emails instead of sending |
| `ENABLE_DEBUG_ROUTES` | `true` to enable `/test-email` and debug detection routes |
| `MAX_UPLOAD_MB` | Max upload size in megabytes (default: 16) |
| `ADMIN_ACCESS_KEY` | Optional key for remote access to `/history` and `/stats` |

**Never commit `.env` to Git.** Only `.env.example` is tracked.

---

## Running the App

From the project root (the folder containing `app.py`):

```powershell
.\venv\Scripts\python.exe app.py    # Windows
```

```bash
python app.py                          # macOS / Linux
```

Use the URL printed in the terminal, for example:

**http://127.0.0.1:5000**

On startup you should see:

```
INFO:__main__:HerLens deepfake engine: opencv-yunet-v2
INFO:__main__:YuNet model ready: True
INFO:__main__:Open the app at http://127.0.0.1:5000
```

If port 5000 is already in use, the app automatically tries **5001** — always open the URL shown in the terminal.

---

## Usage

### Analyze an image

1. Go to the home page.
2. Upload an image (JPG, PNG, GIF, WEBP, BMP — max 16 MB).
3. Enter your email address.
4. View the risk assessment and preview on the results page.
5. Check your email for the PDF password.
6. Download the encrypted report from the results page (link includes a signed token).

### Verify a report

Reports **cannot** be verified with an analysis ID alone. Use the values from **section 5** of the PDF:

1. Open **http://127.0.0.1:5000/verify-timestamp**
2. Paste the **Document Hash** and **Digital Signature** from the PDF.
3. Click **Verify Timestamp**.

A valid report shows **SIGNATURE VALID** with matching integrity checks.

You can also test verification from the command line:

```powershell
.\venv\Scripts\python.exe test_verify.py
```

### Admin pages

| Route | Description |
|-------|-------------|
| `/history` | Recent analyses |
| `/stats` | Usage statistics |
| `/user/<email>` | Analyses for one user |

These routes are available on **localhost** by default. For remote access, set `ADMIN_ACCESS_KEY` in `.env` and use:

```
http://your-domain/history?access_key=YOUR_KEY
```

---

## Project Structure

```
.
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── .env.example            # Environment template (safe to commit)
├── .env                    # Your secrets (gitignored — do not commit)
├── .gitignore
├── models/                 # OpenCV YuNet face model (auto-downloaded if missing)
├── add_timestamp_columns.py
├── test_verify.py          # CLI helper to test timestamp verification
├── templates/              # HTML templates
├── static/uploads/         # Stored upload images (gitignored)
├── uploads/                # Generated PDF reports (gitignored)
├── instance/               # SQLite database (gitignored)
└── tests/
```

---

## Security

- Secrets and credentials live in `.env` only.
- PDF downloads require a signed token (not guessable by filename).
- Uploads are type-checked, size-limited, and stored under random filenames.
- PDF passwords are emailed to the user and **not** stored in the database.
- Debug and test routes are disabled unless `ENABLE_DEBUG_ROUTES=true`.
- Sensitive folders (`uploads/`, `instance/`, `.env`) are in `.gitignore`.
- Timestamp verification requires hash + signature from the PDF, not just an analysis number.

### Production checklist

- Set `FLASK_DEBUG=false`
- Use strong random values for `FLASK_SECRET_KEY` and `TIMESTAMP_SECRET`
- Set `ENABLE_DEBUG_ROUTES=false`
- Set `TESTING_MODE=false`
- Use HTTPS and update `APP_BASE_URL` to your real domain

---

## Troubleshooting

### `can't open file app.py`

Make sure you are in the inner project folder (where `app.py` lives), not the parent download folder.

### Still seeing old results (e.g. 40% deepfake score)

You may have **multiple Flask servers** running on the same port. Each restart without stopping the old server leaves a zombie process.

1. Open Task Manager → end extra `python.exe` processes, or run:
   ```powershell
   netstat -ano | findstr ":5000"
   taskkill /F /PID <pid>
   ```
2. Start **one** server: `.\venv\Scripts\python.exe app.py`
3. Use the **exact URL** printed in the terminal (may be port 5001).
4. Hard-refresh the browser (**Ctrl+F5**) and upload again.

### `DeepFace not available` / TensorFlow DLL error

This warning is safe to ignore. OpenCV YuNet handles deepfake detection without TensorFlow. To enable DeepFace as well:

- Use Python 3.10 or 3.11
- Reinstall: `pip install tensorflow`
- Install [Microsoft Visual C++ Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist) on Windows

### Email not sending

- Confirm `SENDER_PASSWORD` is a Gmail **App Password**, not your normal Gmail password.
- Set `TESTING_MODE=true` to test without sending real email.
- Visit `/test-email` when `ENABLE_DEBUG_ROUTES=true`.

### Git push errors

You must commit before pushing:

```bash
git add .
git commit -m "Your message"
git push -u origin main
```

---

## License

This project is for educational and research purposes. Use responsibly and in compliance with applicable laws and platform policies.

---

## Author

**Srinidhi S** — [GitHub](https://github.com/srinidhis1605)

Repository: [HerLens-AI-Deepfake-Detection-Platform](https://github.com/srinidhis1605/HerLens-AI-Deepfake-Detection-Platform)
