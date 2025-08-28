import socket
import re
import concurrent.futures
import os
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
    ConversationHandler,
    CallbackQueryHandler,
)
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# تمكين التسجيل للمساعدة في تصحيح الأخطاء
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# الإعدادات الهامة (سيتم قراءتها من متغيرات البيئة)
# -----------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ADMIN_ID = int(os.getenv("ADMIN_ID", 0))
# -----------------------------------------------------------------------------

# تخزين البيانات في الذاكرة بدلاً من ملفات JSON
user_settings = {}  # {user_id: {'port': 3389, 'timeout': 2, 'concurrency': 15}}
all_users = set()   # مجموعة من معرفات المستخدمين
saved_online = []   # قائمة بالنتائج المحفوظة

# --- States for ConversationHandler ---
CHOOSING, TYPING_REPLY = range(2)

# --- Web Server for UptimeRobot ---
class KeepAliveHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"Bot is running.")
    
    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

def run_keep_alive_server():
    port = int(os.environ.get('PORT', 8080))
    server_address = ('', port)
    httpd = HTTPServer(server_address, KeepAliveHandler)
    httpd.serve_forever()

# --- User Tracking and Settings Functions ---
def track_user(user_id):
    user_id_str = str(user_id)
    if user_id_str not in all_users:
        all_users.add(user_id_str)

# --- Core Checking Logic ---
def check_rdp(line_info):
    line, default_port, timeout = line_info['line'], line_info['default_port'], line_info['timeout']
    result = {'line': line, 'status': 'Invalid', 'updatedLine': line}
    match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[:;]\s*(\d+))?.*', line)
    ip, port_to_check, line_had_port = (None, default_port, False)
    if match:
        ip = match.group(1)
        if match.group(2):
            port_to_check = int(match.group(2))
            line_had_port = True
    if ip and re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port_to_check))
            result['status'] = 'Online'
            if not line_had_port:
                result['updatedLine'] = f"{ip}:{port_to_check}"
        except (socket.timeout, socket.error):
            result['status'] = 'Offline'
        finally:
            s.close()
    else:
        result['status'] = 'Invalid'
    return result

# --- Central Scan Logic ---
async def run_scan_logic(lines, update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    
    # الحصول على إعدادات المستخدم مع القيم الافتراضية
    user_setting = user_settings.get(user_id, {})
    port = user_setting.get('port', 3389)
    timeout = user_setting.get('timeout', 2)
    concurrency = user_setting.get('concurrency', 15)
    
    # التأكد من أن القيم ضمن النطاق المسموح
    if not (1 <= port <= 65535):
        port = 3389
    if not (1 <= timeout <= 10):
        timeout = 2
    if not (1 <= concurrency <= 50):
        concurrency = 15
    
    status_message = await update.message.reply_text(f"🔍 Received {len(lines)} lines. Starting scan...")
    tasks = [{'line': line, 'default_port': port, 'timeout': timeout} for line in lines]
    online_results, offline_results, invalid_results = [], [], []
    checked_count = 0
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(check_rdp, task) for task in tasks]
            for future in concurrent.futures.as_completed(futures):
                try:
                    res = future.result()
                    if res['status'] == 'Online':
                        online_results.append(res['updatedLine'])
                    elif res['status'] == 'Offline':
                        offline_results.append(res['line'])
                    else:
                        invalid_results.append(res['line'])
                    checked_count += 1
                    if checked_count % 5 == 0 or checked_count == len(lines):
                         await context.bot.edit_message_text(
                            chat_id=update.effective_chat.id,
                            message_id=status_message.message_id,
                            text=f"🔍 Scanning... ({checked_count}/{len(lines)})"
                        )
                except Exception as e:
                    logger.error(f"An error occurred during processing: {e}")
                    invalid_results.append(f"Error processing line: {res.get('line', 'Unknown')}")

        if online_results:
            # حفظ النتائج الجديدة
            for item in online_results:
                if item not in saved_online:
                    saved_online.append(item)

        report_content = ["📊 *RDP Scan Results* 📊", "="*20, f"*Total:* {len(lines)}"]
        if online_results:
            report_content.extend([f"\n*✅ Online: {len(online_results)}*", *online_results])
        if offline_results:
            report_content.extend([f"\n*❌ Offline: {len(offline_results)}*", *offline_results])
        if invalid_results:
            report_content.extend([f"\n*⚠️ Invalid: {len(invalid_results)}*", *invalid_results])
        final_report = "\n".join(report_content)
        
        # تقسيم التقرير إذا كان طويلاً جداً
        if len(final_report) > 4000:
            parts = [final_report[i:i+4000] for i in range(0, len(final_report), 4000)]
            for part in parts:
                await context.bot.send_message(chat_id=update.effective_chat.id, text=part, parse_mode='Markdown')
        else:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id, 
                message_id=status_message.message_id, 
                text=final_report, 
                parse_mode='Markdown'
            )
            
        report_filename = "RDP_Check_Results.txt"
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(final_report.replace('*', ''))
        with open(report_filename, 'rb') as f:
            await context.bot.send_document(chat_id=update.effective_chat.id, document=f)
            
    except Exception as e:
        logger.error(f"Error in run_scan_logic: {e}")
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=status_message.message_id,
            text=f"❌ An error occurred during scanning: {str(e)}"
        )

# --- Telegram Bot Handlers ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    track_user(update.effective_user.id)
    await update.message.reply_text(
        "Welcome to the RDP Status Checker Bot!\n\n"
        "Send me a list of RDPs (one per line) or upload a .txt file to start scanning.\n\n"
        "Use /help to see all available commands."
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    track_user(update.effective_user.id)
    user_id = update.effective_user.id
    help_text = (
        "Here are the available commands:\n\n"
        "*/start* - Shows the welcome message.\n"
        "*/help* - Shows this help message.\n"
        "*/settings* - View and change your scan settings.\n"
        "*/reset* - Resets your settings to the default values."
    )
    if user_id == ADMIN_ID:
        help_text += (
            "\n\n*Admin Commands:*\n"
            "*/stats* - Shows bot usage statistics.\n"
            "*/saved* - View all saved online results.\n"
            "*/clearsaved* - Clear all saved online results."
        )
    await update.message.reply_text(help_text, parse_mode='Markdown')

async def settings_entry_point(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = str(update.effective_user.id)
    track_user(user_id)
    
    user_setting = user_settings.get(user_id, {})
    port = user_setting.get('port', 3389)
    timeout = user_setting.get('timeout', 2)
    concurrency = user_setting.get('concurrency', 15)
    
    keyboard = [
        [InlineKeyboardButton(f"Change Port ({port})", callback_data='change_port')],
        [InlineKeyboardButton(f"Change Timeout ({timeout}s)", callback_data='change_timeout')],
        [InlineKeyboardButton(f"Change Concurrency ({concurrency})", callback_data='change_concurrency')],
        [InlineKeyboardButton("Done", callback_data='done')],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    message = await update.message.reply_text("⚙️ Current Settings:", reply_markup=reply_markup)
    context.user_data['settings_message_id'] = message.message_id
        
    return CHOOSING

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    
    choice = query.data
    context.user_data['choice'] = choice

    if choice == 'done':
        await query.edit_message_text(text="✅ Settings menu closed.")
        return ConversationHandler.END

    prompt_text = {
        'change_port': "Please enter the new default port (1-65535):",
        'change_timeout': "Please enter the new timeout in seconds (1-10):",
        'change_concurrency': "Please enter the new concurrency level (1-50):"
    }

    await query.edit_message_text(text=prompt_text[choice])
    return TYPING_REPLY

async def change_port_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    track_user(update.effective_user.id)
    context.user_data['choice'] = 'change_port'
    await update.message.reply_text("Please enter the new default port (1-65535):")
    return TYPING_REPLY

async def change_timeout_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    track_user(update.effective_user.id)
    context.user_data['choice'] = 'change_timeout'
    await update.message.reply_text("Please enter the new timeout in seconds (1-10):")
    return TYPING_REPLY

async def change_concurrency_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    track_user(update.effective_user.id)
    context.user_data['choice'] = 'change_concurrency'
    await update.message.reply_text("Please enter the new concurrency level (1-50):")
    return TYPING_REPLY

async def received_setting_value(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = str(update.effective_user.id)
    choice = context.user_data.get('choice')
    text = update.message.text
    
    try:
        value = int(text)
        if user_id not in user_settings:
            user_settings[user_id] = {}

        key_map = {'change_port': 'port', 'change_timeout': 'timeout', 'change_concurrency': 'concurrency'}
        setting_key = key_map.get(choice)
        if setting_key is None:
            await update.message.reply_text("An error occurred: unknown setting. Please try /settings again.")
            context.user_data.clear()
            return ConversationHandler.END
        
        # التحقق من النطاقات المسموحة
        if (setting_key == 'port' and not 1 <= value <= 65535) or \
           (setting_key == 'timeout' and not 1 <= value <= 10) or \
           (setting_key == 'concurrency' and not 1 <= value <= 50):
            await update.message.reply_text("Value is out of the allowed range. Please try again or type /cancel.")
            return TYPING_REPLY

        user_settings[user_id][setting_key] = value
        await update.message.reply_text(f"✅ {setting_key.capitalize()} updated to {value}.")
    
    except (ValueError, KeyError):
        await update.message.reply_text("Invalid input. Please enter a valid number.")
        return TYPING_REPLY

    context.user_data.clear()
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancels and ends the conversation."""
    if 'settings_message_id' in context.user_data:
        try:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=context.user_data['settings_message_id'],
                text="Operation cancelled."
            )
        except Exception:
            pass
    else:
        await update.message.reply_text("Operation cancelled.")
        
    context.user_data.clear()
    return ConversationHandler.END

async def reset_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = str(update.effective_user.id)
    track_user(user_id)
    if user_id in user_settings:
        user_settings[user_id] = {}
    await update.message.reply_text("⚙️ All your settings have been reset to default.")

async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_ID: 
        return
    await update.message.reply_text(f"📊 Bot Stats:\nThere are currently {len(all_users)} unique users who have interacted with the bot.")

async def show_saved(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_ID: 
        return
    if not saved_online:
        await update.message.reply_text("🗂️ The saved results list is currently empty.")
        return
    report_text = f"🗂️ Saved Online RDPs ({len(saved_online)}):\n\n" + "\n".join(saved_online)
    if len(report_text) > 4000:
        with open("saved_results.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(saved_online))
        with open("saved_results.txt", "rb") as f:
            await context.bot.send_document(chat_id=update.effective_chat.id, document=f, caption="Here are all the saved online results.")
        os.remove("saved_results.txt")
    else:
        await update.message.reply_text(report_text)

async def clear_saved(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_ID: 
        return
    saved_online.clear()
    await update.message.reply_text("🗑️ All saved online results have been cleared.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # تحقق مما إذا كان المستخدم في حالة محادثة (إعدادات)
    if context.user_data.get('choice'):
        # إذا كان المستخدم في منتصف تغيير الإعدادات، تجاهل الرسالة
        # وسيتم معالجتها بواسطة received_setting_value
        return
    
    track_user(update.effective_user.id)
    
    # تجاهل الرسائل التي تبدأ بشرطة مائلة (أوامر)
    if update.message.text.startswith('/'):
        return
    
    lines = [line.strip() for line in update.message.text.split('\n') if line.strip()]
    is_valid_list = any(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line) for line in lines)
    if is_valid_list:
        await run_scan_logic(lines, update, context)
    else:
        await update.message.reply_text(
            "It seems this is not a valid RDP list. Please send a message with one of the following formats per line:\n\n"
            "`123.45.67.89`\n"
            "`123.45.67.89:8080`\n"
            "`123.45.67.89;3389`\n"
            "`123.45.67.89:3389@user;pass`",
            parse_mode='Markdown'
        )

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # تحقق مما إذا كان المستخدم في حالة محادثة (إعدادات)
    if context.user_data.get('choice'):
        # إذا كان المستخدم في منتصف تغيير الإعدادات، تجاهل الملف
        await update.message.reply_text("Please finish changing your settings before uploading files.")
        return
        
    track_user(update.effective_user.id)
    file = await context.bot.get_file(update.message.document.file_id)
    file_path = f"{update.message.document.file_id}.txt"
    await file.download_to_drive(file_path)
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]
    os.remove(file_path)
    if lines:
        await run_scan_logic(lines, update, context)
    else:
        await update.message.reply_text("The uploaded file is empty.")

def main() -> None:
    if not TELEGRAM_BOT_TOKEN or not ADMIN_ID:
        print("!!! ERROR: Please set TELEGRAM_BOT_TOKEN and ADMIN_ID environment variables !!!")
        return

    keep_alive_thread = threading.Thread(target=run_keep_alive_server)
    keep_alive_thread.daemon = True
    keep_alive_thread.start()
    print("Keep-alive server started.")

    # إنشاء التطبيق مع إعدادات إضافية
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # إنشاء ConversationHandler للإعدادات
    settings_conv_handler = ConversationHandler(
        entry_points=[CommandHandler("settings", settings_entry_point)],
        states={
            CHOOSING: [CallbackQueryHandler(button_callback)],
            TYPING_REPLY: [MessageHandler(filters.TEXT & ~filters.COMMAND, received_setting_value)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        allow_reentry=True
    )

    # إضافة الhandlers بالترتيب الصحيح
    application.add_handler(settings_conv_handler)
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("reset", reset_settings))
    application.add_handler(CommandHandler("stats", stats))
    application.add_handler(CommandHandler("saved", show_saved))
    application.add_handler(CommandHandler("clearsaved", clear_saved))
    application.add_handler(CommandHandler("change_port", change_port_cmd))
    application.add_handler(CommandHandler("change_timeout", change_timeout_cmd))
    application.add_handler(CommandHandler("change_concurrency", change_concurrency_cmd))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(MessageHandler(filters.Document.TEXT, handle_file))

    # تشغيل البوت
    print("Bot is running...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
