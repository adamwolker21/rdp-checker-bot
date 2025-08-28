from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    filters, ConversationHandler, CallbackQueryHandler,
    ContextTypes
)

# ثوابت
CHOOSING, TYPING_REPLY = range(2)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("Change Port", callback_data='change_port')],
        [InlineKeyboardButton("Change Timeout", callback_data='change_timeout')],
        [InlineKeyboardButton("Exit", callback_data='exit')]
    ]
    await update.message.reply_text(
        "اختر الإعداد الذي تريد تغييره:",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return CHOOSING

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.data == 'change_port':
        await query.edit_message_text("أدخل المنفذ الجديد:")
        context.user_data['setting'] = 'port'
        return TYPING_REPLY
    elif query.data == 'change_timeout':
        await query.edit_message_text("أدخل قيمة الـ Timeout الجديدة:")
        context.user_data['setting'] = 'timeout'
        return TYPING_REPLY
    elif query.data == 'exit':
        await query.edit_message_text("تم الخروج من الإعدادات.")
        return ConversationHandler.END

async def received_value(update: Update, context: ContextTypes.DEFAULT_TYPE):
    value = update.message.text
    setting = context.user_data.get('setting')
    await update.message.reply_text(f"تم تغيير {setting} إلى {value}")
    return ConversationHandler.END

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("استخدم /start لبدء الإعدادات.")

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    await update.message.reply_text(f"تم استقبال الملف: {doc.file_name}")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("تم استقبال الرسالة.")

def main():
    application = ApplicationBuilder().token("YOUR_BOT_TOKEN").build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            CHOOSING: [CallbackQueryHandler(button_callback)],
            TYPING_REPLY: [MessageHandler(filters.TEXT & ~filters.COMMAND, received_value)],
        },
        fallbacks=[CommandHandler('start', start)],
        per_message=True
    )

    application.add_handler(conv_handler)
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    application.run_polling()

if __name__ == "__main__":
    main()
