import socket
import re
import concurrent.futures
import os
import json
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

# -----------------------------------------------------------------------------
# الإعدادات الهامة (سيتم قراءتها من متغيرات البيئة)
# -----------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ADMIN_ID = int(os.getenv("ADMIN_ID", 0))
# -----------------------------------------------------------------------------

USER_SETTINGS_FILE = "user_settings.json"
ALL_USERS_FILE = "all_users.json"
SAVED_ONLINE_FILE = "saved_online.json"

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
def load_json_file(filename, default_type=list):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return default_type()
    return default_type()

def save_json_file(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def track_user(user_id):
    user_id_str = str(user_id)
    all_users = load_json_file(ALL_USERS_FILE, default_type=list)
    if user_id_str not in all_users:
        all_users.append(user_id_str)
        save_json_file(all_users, ALL_USERS_FILE)

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
    all_settings = load_json_file(USER_SETTINGS_FILE, default_type=dict)
    user_settings = all_settings.get(user_id, {'port': 3389, 'timeout': 2, 'concurrency': 15})
    status_message = await update.message.reply_text(f"🔍 Received {len(lines)} lines. Starting scan...")
    tasks = [{'line': line, 'default_port': user_settings['port'], 'timeout': user_settings['timeout']} for line in lines]
    online_results, offline_results, invalid_results = [], [], []
    checked_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=user_settings['concurrency']) as executor:
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
                print(f"An error occurred during processing: {e}")

    if online_results:
        saved_online = load_json_file(SAVED_ONLINE_FILE, default_type=list)
        new_items = [item for item in online_results if item not in saved_online]
        saved_online.extend(new_items)
        save_json_file(saved_online, SAVED_ONLINE_FILE)

    report_content = ["📊 *RDP Scan Results* 📊", "="*20, f"*Total:* {len(lines)}"]
    if online_results:
        report_content.extend([f"\n*✅ Online: {len(online_results)}*", *online_results])
    if offline_results:
        report_content.extend([f"\n*❌ Offline: {len(offline_results)}*", *offline_results])
    if invalid_results:
        report_content.extend([f"\n*⚠️ Invalid: {len(invalid_results)}*", *invalid_results])
    final_report = "\n".join(report_content)
    await context.bot.edit_message_text(chat_id=update.effective_chat.id, message_id=status_message.message_id, text=final_report, parse_mode='Markdown')
    report_filename = "RDP_Check_Results.txt"
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(final_report.replace('*', ''))
    with open(report_filename, 'rb') as f:
        await context.bot.send_document(chat_id=update.effective_chat.id, document=f)

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
    all_settings = load_json_file(USER_SETTINGS_FILE, default_type=dict)
    user_settings = all_settings.get(user_id, {})
    port = user_settings.get('port', 3389)
    timeout = user_settings.get('timeout', 2)
    concurrency = user_settings.get('concurrency', 15)
    
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
    # أجب عن ال callback فوراً حتى لا يبقى الزر معلقاً في الواجهة
    try:
        await query.answer(text="Processing...", show_alert=False)
    except Exception:
        # في حال فشل الرد السريع، تجاهل واستمر
        pass

    choice = query.data
    context.user_data['choice'] = choice

    if choice == 'done':
        # أغلق القائمة ونهي المحادثة
        try:
            await query.edit_message_text(text="✅ Settings menu closed.")
        except Exception:
            pass
        context.user_data.clear()
        return ConversationHandler.END

    prompt_text = {
        'change_port': "Please enter the new default port:",
        'change_timeout': "Please enter the new timeout in seconds (1-10):",
        'change_concurrency': "Please enter the new concurrency level (1-50):"
    }

    # حاول تعديل رسالة القوائم، وإن لم ينجح أرسل رسالة عادية
    try:
        await query.edit_message_text(text=prompt_text[choice])
    except Exception:
        try:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=prompt_text[choice])
        except Exception:
            # إذا فشل أيضاً، سجل وانهِ المحادثة بأمان
            print('Failed to prompt user for setting value.')
            context.user_data.clear()
            return ConversationHandler.END

    return TYPING_REPLY

# New command entry points so users can also use /change_port etc.
async def change_port_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    track_user(update.effective_user.id)
    context.user_data['choice'] = 'change_port'
    await update.message.reply_text("Please enter the new default port:")
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
        all_settings = load_json_file(USER_SETTINGS_FILE, default_type=dict)
        if user_id not in all_settings:
            all_settings[user_id] = {}

        key_map = {'change_port': 'port', 'change_timeout': 'timeout', 'change_concurrency': 'concurrency'}
        setting_key = key_map.get(choice)
        if setting_key is None:
            await update.message.reply_text("An error occurred: unknown setting. Please try /settings again.")
            context.user_data.clear()
            return ConversationHandler.END
        
        if (setting_key == 'timeout' and not 1 <= value <= 10) or \
           (setting_key == 'concurrency' and not 1 <= value <= 50):
            await update.message.reply_text("Value is out of the allowed range. Please try again or type /cancel.")
            return TYPING_REPLY

        all_settings[user_id][setting_key] = value
        save_json_file(all_settings, USER_SETTINGS_FILE)
        
        await update.message.reply_text(f"✅ {setting_key.capitalize()} updated to {value}.")
    
    except (ValueError, KeyError):
        await update.message.reply_text("Invalid input. Please enter a valid number.")
        return TYPING_REPLY

    # If we opened settings menu previously, try to delete/edit it; if not, ignore safely
    if 'settings_message_id' in context.user_data:
        try:
            await context.bot.delete_message(chat_id=update.effective_chat.id, message_id=context.user_data['settings_message_id'])
        except Exception:
            pass

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
            pass # Message might have been deleted already
    else:
        await update.message.reply_text("Operation cancelled.")
        
    context.user_data.clear()
    return ConversationHandler.END

async def reset_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = str(update.effective_user.id)
    track_user(user_id)
    all_settings = load_json_file(USER_SETTINGS_FILE, default_type=dict)
    if user_id in all_settings:
        all_settings[user_id] = {}
        save_json_file(all_settings, USER_SETTINGS_FILE)
    await update.message.reply_text("⚙️ All your settings have been reset to default.")

async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_ID: return
    all_users = load_json_file(ALL_USERS_FILE, default_type=list)
    await update.message.reply_text(f"📊 Bot Stats:\nThere are currently {len(all_users)} unique users who have interacted with the bot.")

async def show_saved(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_ID: return
    saved_online = load_json_file(SAVED_ONLINE_FILE, default_type=list)
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
    if update.effective_user.id != ADMIN_ID: return
    save_json_file([], SAVED_ONLINE_FILE)
    await update.message.reply_text("🗑️ All saved online results have been cleared.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    track_user(update.effective_user.id)
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

# --- Fallback handler for clients that send the menu button text as a normal message
# Some Telegram clients (or keyboard types) send the button label as a regular message
# instead of a CallbackQuery. To support those clients, map the visible menu texts
# to the same command handlers.
async def menu_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.message.text or "").strip()
    # Map substrings because buttons include current values like 'Change Port (3389)'
    try:
        if 'Change Port' in text:
            await change_port_cmd(update, context)
            return
        if 'Change Timeout' in text:
            await change_timeout_cmd(update, context)
            return
        if 'Change Concurrency' in text:
            await change_concurrency_cmd(update, context)
            return
        if text.lower() == 'done' or 'done' in text:
            # behave like pressing Done
            await cancel(update, context)
            return
    except Exception as e:
        print(f"menu_text_handler error: {e}")
        # fall through to normal handlers if mapping fails

    # If it wasn't one of our menu texts, pass to the normal message handler
    await handle_message(update, context)


def main() -> None:
    if not TELEGRAM_BOT_TOKEN or not ADMIN_ID:
        print("!!! ERROR: Please set TELEGRAM_BOT_TOKEN and ADMIN_ID environment variables !!!")
        return

    keep_alive_thread = threading.Thread(target=run_keep_alive_server)
    keep_alive_thread.daemon = True
    keep_alive_thread.start()
    print("Keep-alive server started.")

    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # ConversationHandler now accepts multiple entry points including direct /change_* commands
    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler("settings", settings_entry_point),
            CommandHandler("change_port", change_port_cmd),
            CommandHandler("change_timeout", change_timeout_cmd),
            CommandHandler("change_concurrency", change_concurrency_cmd),
        ],
        states={
            CHOOSING: [CallbackQueryHandler(button_callback)],
            TYPING_REPLY: [MessageHandler(filters.TEXT & ~filters.COMMAND, received_setting_value)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        per_message=False
    )

    application.add_handler(conv_handler)
    # إضافة معالج عام للتعامل مع callback queries حتى لو لم تكن ConversationHandler في حالة متوقعة
    application.add_handler(CallbackQueryHandler(button_callback))
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("reset", reset_settings))
    application.add_handler(CommandHandler("stats", stats))
    application.add_handler(CommandHandler("saved", show_saved))
    application.add_handler(CommandHandler("clearsaved", clear_saved))
    # Also register the change_* commands so they can be called outside the conversation if needed
    application.add_handler(CommandHandler("change_port", change_port_cmd))
    application.add_handler(CommandHandler("change_timeout", change_timeout_cmd))
    application.add_handler(CommandHandler("change_concurrency", change_concurrency_cmd))

    # First handle cases where the client sent the menu button text as a message
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, menu_text_handler))
    # Then the general text handler (scans, etc.)
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(MessageHandler(filters.Document.TEXT, handle_file))

    print("Bot is running...")
    application.run_polling()

if __name__ == "__main__":
    main()
