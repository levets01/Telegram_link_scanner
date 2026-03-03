import os
import requests
import validators
import base64
from urllib.parse import urlparse
from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, filters, ContextTypes

# =========================
# VARIABLES DE ENTORNO
# =========================

TOKEN = os.environ.get("TOKEN")
VT_API_KEY = os.environ.get("VT_API_KEY")
TU_USER_ID = int(os.environ.get("TU_USER_ID"))

# =========================
# FUNCIÓN PRINCIPAL
# =========================

async def analizar(update: Update, context: ContextTypes.DEFAULT_TYPE):

    # 🔐 Solo tú puedes usar el bot
    if update.effective_user.id != TU_USER_ID:
        await update.message.reply_text("⛔ No autorizado.")
        return

    url = update.message.text.strip()

    if not validators.url(url):
        await update.message.reply_text("❌ URL inválida.")
        return

    await update.message.reply_text("🔎 Consultando reputación...")

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        # Codificar URL en base64 (requerido por VT)
        url_bytes = url.encode()
        url_id = base64.urlsafe_b64encode(url_bytes).decode().strip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers
        )

        if response.status_code == 404:
            await update.message.reply_text("⚠️ URL no encontrada en base de datos.")
            return

        if response.status_code != 200:
            await update.message.reply_text(
                f"❌ Error API: {response.status_code}\n{response.text}"
            )
            return

        data = response.json()["data"]["attributes"]
        stats = data["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        parsed = urlparse(url)
        dominio = parsed.netloc

        # Evaluación
        if malicious >= 1:
            riesgo = "🚨 PELIGROSO 🚨"
        elif suspicious >= 1:
            riesgo = "🟡 SOSPECHOSO"
        else:
            riesgo = "✅ Sin detecciones conocidas"

        mensaje = (
            f"{riesgo}\n\n"
            f"🌐 Dominio: {dominio}\n\n"
            f"Malicious: {malicious}\n"
            f"Suspicious: {suspicious}\n"
            f"Harmless: {harmless}\n"
            f"Undetected: {undetected}"
        )

        await update.message.reply_text(mensaje)

    except Exception as e:
        await update.message.reply_text(f"⚠️ Error interno:\n{str(e)}")


# =========================
# INICIAR BOT
# =========================

app = ApplicationBuilder().token(TOKEN).build()
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, analizar))

print("🤖 Bot activo en Render...")
app.run_polling()