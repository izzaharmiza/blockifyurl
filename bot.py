import requests
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters

# Your API endpoint
API_URL = "https://your-app-name.herokuapp.com/api/predict"

# Telegram bot token
TOKEN = '7252862437:AAHkwQdb-AR9Qq3GaVvG467EOlpNCs6AHKY'

def start(update, context):
    update.message.reply_text('Send me a URL to check for phishing.')

def check_url(update, context):
    url = update.message.text
    response = requests.post(API_URL, json={"url": url})
    result = response.json()
    
    if "error" in result:
        update.message.reply_text(f"Error: {result['error']}")
    else:
        message = (
            f"Prediction: {'Phishing' if result['prediction'] == 1 else 'Safe'}\n"
            f"Probability Safe: {result['probability_safe'] * 100:.2f}%\n"
            f"Probability Phishing: {result['probability_phishing'] * 100:.2f}%\n"
            f"Message: {result['message']}"
        )
        update.message.reply_text(message)

def main():
    updater = Updater(TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, check_url))

    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
     app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
