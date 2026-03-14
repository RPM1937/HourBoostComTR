import smtplib
import logging
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
MAIL_FROM = os.environ.get("MAIL_FROM", MAIL_USERNAME)
SITE_URL = os.environ.get("SITE_URL", "https://hourboost.com.tr")


def send_email(to_email, subject, html_body):
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        logger.error("Mail ayarlari eksik")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"HourBoost <{MAIL_FROM}>"
        msg["To"] = to_email
        part = MIMEText(html_body, "html", "utf-8")
        msg.attach(part)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.sendmail(MAIL_FROM, to_email, msg.as_string())
        logger.info("Mail gonderildi: %s -> %s", subject, to_email)
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error("Gmail kimlik dogrulama hatasi")
        return False
    except smtplib.SMTPException as e:
        logger.error("SMTP hatasi: %s", e)
        return False
    except Exception as e:
        logger.error("Mail gonderme hatasi: %s", e)
        return False


def _base_template(header_icon, header_title, body_html):
    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#0d0e12;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d0e12;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="100%" style="max-width:520px;background:#13151b;border-radius:16px;border:1px solid rgba(255,255,255,0.07);overflow:hidden;">
          <tr>
            <td style="background:linear-gradient(135deg,#00c98b,#00a572);padding:32px;text-align:center;">
              <div style="font-size:28px;margin-bottom:8px;">{header_icon}</div>
              <div style="font-size:22px;font-weight:700;color:#001a0f;letter-spacing:1px;">HOUR BOOST</div>
              <div style="font-size:13px;color:rgba(0,26,15,0.7);margin-top:4px;">{header_title}</div>
            </td>
          </tr>
          <tr>
            <td style="padding:36px 32px;">
              {body_html}
            </td>
          </tr>
          <tr>
            <td style="padding:20px 32px;border-top:1px solid rgba(255,255,255,0.07);text-align:center;">
              <p style="margin:0;font-size:12px;color:#3a4050;">
                &copy; 2026 HourBoost &nbsp;·&nbsp;
                <a href="{SITE_URL}/gizlilik" style="color:#5a6070;text-decoration:none;">Gizlilik</a>
                &nbsp;·&nbsp;
                <a href="{SITE_URL}/kullanim-sartlari" style="color:#5a6070;text-decoration:none;">Kullanım Şartları</a>
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def send_verification_email(to_email, username, token):
    verify_url = f"{SITE_URL}/verify-email/{token}"
    body = f"""
      <p style="margin:0 0 8px;font-size:13px;color:#5a6070;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Merhaba,</p>
      <h1 style="margin:0 0 20px;font-size:22px;font-weight:700;color:#e8eaf0;">{username}</h1>
      <p style="margin:0 0 28px;font-size:15px;color:#8892a0;line-height:1.7;">
        HourBoost'a hoş geldin! Hesabını aktifleştirmek için aşağıdaki butona tıklayarak e-posta adresini doğrula.
      </p>
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center" style="padding:0 0 28px;">
            <a href="{verify_url}" style="display:inline-block;padding:14px 36px;background:linear-gradient(135deg,#00c98b,#00a572);color:#001a0f;font-weight:700;font-size:15px;text-decoration:none;border-radius:10px;">
              ✓ E-postamı Doğrula
            </a>
          </td>
        </tr>
      </table>
      <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.07);border-radius:10px;padding:16px;margin-bottom:24px;">
        <p style="margin:0 0 6px;font-size:12px;color:#5a6070;font-weight:600;text-transform:uppercase;letter-spacing:1px;">Veya bu linki tarayıcına kopyala:</p>
        <p style="margin:0;font-size:12px;color:#00e5a0;word-break:break-all;">{verify_url}</p>
      </div>
      <p style="margin:0;font-size:13px;color:#5a6070;line-height:1.6;">
        Bu link <strong style="color:#8892a0;">24 saat</strong> geçerlidir.<br>
        Eğer bu hesabı sen oluşturmadıysan bu maili görmezden gelebilirsin.
      </p>"""
    html = _base_template("⚡", "Steam Saat Boost Servisi", body)
    return send_email(to_email, "E-posta Adresinizi Doğrulayın — HourBoost", html)


def send_welcome_email(to_email, username):
    body = f"""
      <h1 style="margin:0 0 16px;font-size:20px;font-weight:700;color:#e8eaf0;">Hoş geldin, {username}!</h1>
      <p style="margin:0 0 24px;font-size:15px;color:#8892a0;line-height:1.7;">
        E-posta adresin başarıyla doğrulandı. Artık Steam hesaplarını ekleyip boost'a başlayabilirsin!
      </p>
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center">
            <a href="{SITE_URL}" style="display:inline-block;padding:14px 36px;background:linear-gradient(135deg,#00c98b,#00a572);color:#001a0f;font-weight:700;font-size:15px;text-decoration:none;border-radius:10px;">
              ⚡ Dashboard'a Git
            </a>
          </td>
        </tr>
      </table>"""
    html = _base_template("🎉", "Hesabın Aktif!", body)
    return send_email(to_email, "Hesabın Aktif — HourBoost'a Hoş Geldin!", html)


def send_password_reset_email(to_email, username, token):
    reset_url = f"{SITE_URL}/reset-password/{token}"
    body = f"""
      <p style="margin:0 0 8px;font-size:13px;color:#5a6070;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Merhaba,</p>
      <h1 style="margin:0 0 20px;font-size:22px;font-weight:700;color:#e8eaf0;">{username}</h1>
      <p style="margin:0 0 28px;font-size:15px;color:#8892a0;line-height:1.7;">
        HourBoost hesabın için şifre sıfırlama talebinde bulundun. Yeni şifreni belirlemek için aşağıdaki butona tıkla.
      </p>
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center" style="padding:0 0 28px;">
            <a href="{reset_url}" style="display:inline-block;padding:14px 36px;background:linear-gradient(135deg,#00c98b,#00a572);color:#001a0f;font-weight:700;font-size:15px;text-decoration:none;border-radius:10px;">
              🔑 Şifremi Sıfırla
            </a>
          </td>
        </tr>
      </table>
      <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.07);border-radius:10px;padding:16px;margin-bottom:24px;">
        <p style="margin:0 0 6px;font-size:12px;color:#5a6070;font-weight:600;text-transform:uppercase;letter-spacing:1px;">Veya bu linki tarayıcına kopyala:</p>
        <p style="margin:0;font-size:12px;color:#00e5a0;word-break:break-all;">{reset_url}</p>
      </div>
      <p style="margin:0;font-size:13px;color:#5a6070;line-height:1.6;">
        Bu link <strong style="color:#8892a0;">1 saat</strong> geçerlidir.<br>
        Eğer bu talebi sen yapmadıysan bu maili görmezden gelebilirsin, şifren değişmeyecektir.
      </p>"""
    html = _base_template("🔑", "Şifre Sıfırlama", body)
    return send_email(to_email, "Şifre Sıfırlama Talebi — HourBoost", html)


def send_email_change_email(to_email, username, token):
    confirm_url = f"{SITE_URL}/confirm-email-change/{token}"
    body = f"""
      <p style="margin:0 0 8px;font-size:13px;color:#5a6070;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Merhaba,</p>
      <h1 style="margin:0 0 20px;font-size:22px;font-weight:700;color:#e8eaf0;">{username}</h1>
      <p style="margin:0 0 28px;font-size:15px;color:#8892a0;line-height:1.7;">
        HourBoost hesabının e-posta adresini değiştirme talebinde bulundun. Yeni e-posta adresini doğrulamak için aşağıdaki butona tıkla.
      </p>
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center" style="padding:0 0 28px;">
            <a href="{confirm_url}" style="display:inline-block;padding:14px 36px;background:linear-gradient(135deg,#00c98b,#00a572);color:#001a0f;font-weight:700;font-size:15px;text-decoration:none;border-radius:10px;">
              ✓ Yeni E-postamı Doğrula
            </a>
          </td>
        </tr>
      </table>
      <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.07);border-radius:10px;padding:16px;margin-bottom:24px;">
        <p style="margin:0 0 6px;font-size:12px;color:#5a6070;font-weight:600;text-transform:uppercase;letter-spacing:1px;">Veya bu linki tarayıcına kopyala:</p>
        <p style="margin:0;font-size:12px;color:#00e5a0;word-break:break-all;">{confirm_url}</p>
      </div>
      <p style="margin:0;font-size:13px;color:#5a6070;line-height:1.6;">
        Bu link <strong style="color:#8892a0;">1 saat</strong> geçerlidir.<br>
        Eğer bu talebi sen yapmadıysan bu maili görmezden gelebilirsin.
      </p>"""
    html = _base_template("✉️", "E-posta Değiştirme", body)
    return send_email(to_email, "Yeni E-posta Adresinizi Doğrulayın — HourBoost", html)
