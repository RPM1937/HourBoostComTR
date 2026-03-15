⚡ HourBoost

An automated Steam game hour boosting service. Connect multiple Steam accounts, select your games, and boost your hours automatically — 24/7.

🚀 Features

- 🎮 Multiple Steam account support
- ⏱️ Timed boost — set a timer and stop automatically
- 📊 Per-game boost statistics
- 🔒 Email verification system
- 🔑 Password reset & email change
- 💳 Shopier payment integration
- 🛡️ Brute force protection
- 📱 Active session management (with IP and device info)
- 🌐 Bilingual support (Turkish & English)
- 👤 Admin panel (user management, payment approval, announcements)
- 🔄 Auto reconnect on connection drop

---

📋 Requirements

- Python 3.10+
- pip

## ⚙️ Installation

1. Clone the repository
git clone https://github.com/username/hourboost.git
cd hourboost

2. Create a virtual environment
   
python3 -m venv venv

source venv/bin/activate  #Windows: venv\Scripts\activate

4. Install dependencies
   
pip install -r requirements.txt

6. Set up environment variables
   
cp .env.example .env
nano .env

5-Fill in .env with your own values.

5. Run
   
Development:

python app.py

Production (Gunicorn):

gunicorn -c gunicorn.conf.py app:app

🛡️ Security

Steam passwords are encrypted with Fernet symmetric encryption

JWT token blacklist system

IP and user-based brute force protection (5 failed attempts = 5 min lockout)

Email verification required before adding Steam accounts

CSRF protection on all state-changing endpoints

SQL Injection protection via SQLAlchemy ORM

Shopier webhook signature verification

Duplicate payment prevention via transaction ID check

🌐 Language Support

HourBoost supports both Turkish and English:

Turkish: hourboost.com.tr/

English: hourboost.com.tr/en/
Emails will be sent in Turkish regardless of which option you choose.

⚠️ Disclaimer
Usage that violates Steam's Terms of Service is the sole responsibility of the user.
