import socket
import re
import concurrent.futures
import os
import json
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# -----------------------------------------------------------------------------
# الإعدادات الهامة (سيتم قراءتها من متغيرات البيئة)
# -----------------------------------------------------------------------------
# 1. استبدل هذا بالتوكن الخاص ببوتك
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

# 2. استبدل هذا بالـ ID الخاص بحسابك في تليجرام لتمكين أوامر المدير
ADMIN_ID = int(os.getenv("ADMIN_ID", 0)) 
# -----------------------------------------------------------------------------

USER_SETTINGS_FILE = "user_settings.json"
ALL_USERS_FILE = "all_users.json" # ملف جديد لتتبع كل المستخدمين

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
def load_json_file(filename):
    """Loads a JSON file and returns its content."""
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {} if filename == USER_SETTINGS_FILE else []
    return {} if filename == USER_SETTINGS_FILE else []

def save_json_file(data, filename):
    """Saves data to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def track_user(user_id):
    """Adds a user ID to the list of all users if not already present."""
    user_id_str = str(user_id)
    all_users = load_json_file(ALL_USERS_FILE)
    if user_id_str not in all_users:
        all_users.append(user_id_str)
        save_json_file(all_users, ALL_USERS_FILE)

# --- Core Checking Logic ---
def check_rdp(line_info):
    """
    Checks the status of a single RDP connection.
    """
    line = line_info['line']
    default_port = line_info['default_port']
    timeout = line_info['timeout']
    
    result = {
        'line': line,
        'status': 'Invalid',
        'updatedLine': line
    }

    match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[:;]\s*(\d+))?.*', line)
    
    ip = None
    port_to_check = default_port
    line_had_port = False

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
    """The core logic for scanning a list of lines and reporting results."""
    user_id = str(update.effective_user.id)
    all_settings = load_json_file(USER_SETTINGS_FILE)
    user_settings = all_settings.get(user_id, {'port': 3389, 'timeout': 2, 'concurrency': 15})
    target_channel = user_settings.get('target_channel')

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

    # --- Create Formatted Report String ---
    report_content = [
        "📊 *RDP Scan Results* 📊", "="*20, f"*Total:* {len(lines)}"
    ]
    if online_results:
        report_content.extend([f"\n*✅ Online: {len(online_results)}*", *online_results])
    if offline_results:
        report_content.extend([f"\n*❌ Offline: {len(offline_results)}*", *offline_results])
    if invalid_results:
        report_content.extend([f"\n*⚠️ Invalid: {len(invalid_results)}*", *invalid_results])
    
    final_report = "\n".join(report_content)
    
    final_destination = target_channel if target_channel else update.effective_chat.id

    # --- Send Results ---
    try:
        if not target_channel:
            # If no channel, edit the original message with the full report
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=status_message.message_id,
                text=final_report,
                parse_mode='Markdown'
            )
        else:
            # If channel is set, send a new message to the channel
            await context.bot.send_message(
                chat_id=final_destination,
                text=final_report,
                parse_mode='Markdown'
            )
        
        # Send the file report
        report_filename = "RDP_Check_Results.txt"
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(final_report.replace('*', ''))
        
        with open(report_filename, 'rb') as f:
            await context.bot.send_document(chat_id=final_destination, document=f)

        # Confirm completion to the user
        if target_channel:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=status_message.message_id,
                text=f"✅ Scan complete! Results sent to {final_destination}."
            )

    except Exception as e:
        print(f"Error sending to destination {final_destination}: {e}")
        error_message = (
            f"❌ Scan complete, but failed to send results to {final_destination}.\n\n"
            "Please check if the channel/group ID is correct and that the bot has been added as an administrator."
        )
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=status_message.message_id,
            text=error_message
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
        "*/settings* - Displays your current scan settings.\n"
        "*/set <port> <timeout> <concurrency>* - Sets new values for your settings. \n_Example: `/set 3389 3 20`_\n"
        "*/reset* - Resets your settings to the default values."
    )
    
    if user_id == ADMIN_ID:
        help_text += (
            "\n\n*Admin Commands:*\n"
            "*/stats* - Shows bot usage statistics.\n"
            "*/setchannel <ID or @username>* - Set a channel/group to post results to.\n"
            "*/removechannel* - Stop posting to a channel/group."
        )

    await update.message.reply_text(help_text, parse_mode='Markdown')

async def set_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = str(update.effective_user.id)
    track_user(user_id)
    try:
        parts = context.args
        if len(parts) == 3:
            port, timeout, concurrency = map(int, parts)
            
            all_settings = load_json_file(USER_SETTINGS_FILE)
            if user_id not in all_settings:
                all_settings[user_id] = {}
            all_settings[user_id].update({'port': port, 'timeout': timeout, 'concurrency': concurrency})
            save_json_file(all_settings, USER_SETTINGS_FILE)
            
            await update.message.reply_text(
                f"✅ Settings updated successfully:\n"
                f"- Default Port: {port}\n"
                f"- Timeout: {timeout} seconds\n"
                f"- Concurrency: {concurrency}"
            )
        else:
            await update.message.reply_text("Incorrect usage. Example: /set <port> <timeout> <concurrency>\nExample: /set 3389 2 15")
    except (IndexError, ValueError):
        await update.message.reply_text("Invalid input. Please enter valid numbers for the settings.")

async def show_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = str(update.effective_user.id)
    track_user(user_id)
    all_settings = load_json_file(USER_SETTINGS_FILE)
    user_settings = all_settings.get(user_id, {})
    
    port = user_settings.get('port', 3389)
    timeout = user_settings.get('timeout', 2)
    concurrency = user_settings.get('concurrency', 15)
    
    settings_text = (
        f"⚙️ Current Settings:\n"
        f"- Default Port: {port}\n"
        f"- Timeout: {timeout} seconds\n"
        f"- Concurrency: {concurrency}"
    )

    # Only show the target channel to the admin
    if update.effective_user.id == ADMIN_ID:
        target_channel = user_settings.get('target_channel', 'Private Chat')
        settings_text += f"\n- Post Results To: {target_channel}"

    await update.message.reply_text(settings_text)

async def reset_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = str(update.effective_user.id)
    track_user(user_id)
    all_settings = load_json_file(USER_SETTINGS_FILE)
    if user_id in all_settings:
        all_settings[user_id] = {} # Clear all settings for the user
        save_json_file(all_settings, USER_SETTINGS_FILE)
    await update.message.reply_text("⚙️ All your settings have been reset to default.")
    await show_settings(update, context)

async def set_channel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = str(update.effective_user.id)
    if update.effective_user.id != ADMIN_ID: return # Admin only
    track_user(user_id)
    if not context.args:
        await update.message.reply_text("Please provide a channel/group ID or username. Example: /setchannel @mychannel")
        return
    
    channel_id = context.args[0]
    all_settings = load_json_file(USER_SETTINGS_FILE)
    if user_id not in all_settings:
        all_settings[user_id] = {}
    
    try:
        await context.bot.send_message(chat_id=channel_id, text="✅ Bot connected successfully! Scan results will be posted here.")
        all_settings[user_id]['target_channel'] = channel_id
        save_json_file(all_settings, USER_SETTINGS_FILE)
        await update.message.reply_text(f"Success! Results will now be sent to {channel_id}.")
    except Exception as e:
        print(e)
        await update.message.reply_text(f"Could not connect to {channel_id}. Please make sure the ID is correct and the bot is an admin in the channel/group.")

async def remove_channel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = str(update.effective_user.id)
    if update.effective_user.id != ADMIN_ID: return # Admin only
    track_user(user_id)
    all_settings = load_json_file(USER_SETTINGS_FILE)
    if user_id in all_settings and 'target_channel' in all_settings[user_id]:
        del all_settings[user_id]['target_channel']
        save_json_file(all_settings, USER_SETTINGS_FILE)
        await update.message.reply_text("✅ Success! Results will now be sent to you in this private chat.")
    else:
        await update.message.reply_text("No target channel is currently set.")

async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Admin command to show bot statistics."""
    user_id = update.effective_user.id
    if user_id != ADMIN_ID:
        return

    all_users = load_json_file(ALL_USERS_FILE)
    await update.message.reply_text(f"📊 Bot Stats:\nThere are currently {len(all_users)} unique users who have interacted with the bot.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    track_user(update.effective_user.id)
    lines = [line.strip() for line in update.message.text.split('\n') if line.strip()]
    if lines:
        await run_scan_logic(lines, update, context)
    else:
        await update.message.reply_text("No valid lines found to check. Please send a list of RDPs or a .txt file.")

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    track_user(update.effective_user.id)
    file = await context.bot.get_file(update.message.document.file_id)
    file_path = f"{update.message.document.file_id}.txt"
    await file.download_to_drive(file_path)
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]
    
    os.remove(file_path) # Clean up the downloaded file

    if lines:
        await run_scan_logic(lines, update, context)
    else:
        await update.message.reply_text("The uploaded file is empty.")

def main() -> None:
    """Start the bot."""
    if not TELEGRAM_BOT_TOKEN or not ADMIN_ID:
        print("!!! ERROR: Please set TELEGRAM_BOT_TOKEN and ADMIN_ID environment variables !!!")
        return

    # Start the keep-alive server in a separate thread
    keep_alive_thread = threading.Thread(target=run_keep_alive_server)
    keep_alive_thread.daemon = True
    keep_alive_thread.start()
    print("Keep-alive server started.")

    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("set", set_settings))
    application.add_handler(CommandHandler("settings", show_settings))
    application.add_handler(CommandHandler("reset", reset_settings))
    application.add_handler(CommandHandler("setchannel", set_channel))
    application.add_handler(CommandHandler("removechannel", remove_channel))
    application.add_handler(CommandHandler("stats", stats))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(MessageHandler(filters.Document.TEXT, handle_file))

    print("Bot is running...")
    application.run_polling()

if __name__ == "__main__":
    main()



