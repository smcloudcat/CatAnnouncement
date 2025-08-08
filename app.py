from flask import Flask, session, redirect, url_for, request, render_template, jsonify, abort
from flask_session import Session
import requests
import os
import json
import time
import threading
import smtplib
import logging
import fcntl
import contextlib
from email.mime.text import MIMEText
from datetime import datetime
from config import CLIENT_ID, REDIRECT_URI, AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, USERINFO_ENDPOINT, SCOPE, SUPER_ADMIN_EMAIL, MAIL_SERVER, MAIL_PORT, MAIL_USE_SSL, MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER

app = Flask(__name__)
app.secret_key = os.urandom(24)

# 配置会话
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session'
Session(app)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# 线程锁
user_lock = threading.Lock()
announcements_lock = threading.Lock()
admins_lock = threading.Lock()

LOCK_FILE = "./email_sender.lock"

# 通用上下文文件锁
@contextlib.contextmanager
def file_lock(path):
    lock_file = open(path, 'w')
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)  # 阻塞直到获取
        yield lock_file
    finally:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()

# 数据加载与保存
def load_announcements():
    with announcements_lock:
        try:
            with open('announcements.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

def save_announcements(announcements):
    with announcements_lock:
        with open('announcements.json', 'w', encoding='utf-8') as f:
            json.dump(announcements, f, ensure_ascii=False, indent=2)

def load_users():
    with user_lock:
        try:
            with open('users.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

def save_users(users):
    with user_lock:
        with open('users.json', 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)

def load_admins():
    with admins_lock:
        try:
            with open('admins.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return [SUPER_ADMIN_EMAIL]

def save_admins(admins):
    with admins_lock:
        with open('admins.json', 'w', encoding='utf-8') as f:
            json.dump(admins, f, ensure_ascii=False, indent=2)

# 权限检查
def is_admin(user_email):
    admins = load_admins()
    return user_email in admins

# 发邮件
def send_email(to_email, subject, content):
    try:
        msg = MIMEText(content, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = MAIL_DEFAULT_SENDER[1]
        msg['To'] = to_email

        if MAIL_USE_SSL:
            server = smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT)
        else:
            server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT)
            server.starttls()

        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_DEFAULT_SENDER[1], to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        logger.error(f"邮件发送失败: {str(e)} [PID: {os.getpid()}, TID: {threading.get_ident()}]")
        return False

# 发送状态
email_send_lock = threading.Lock()
last_send_time = {}
failed_attempts = {}

# 邮件发送线程
def email_sender():
    global last_send_time, failed_attempts
    while True:
        try:
            with file_lock(LOCK_FILE):
                users = load_users()
                announcements = load_announcements()

                if announcements and users:
                    current_time = time.time()

                    for user_id, user_data in list(users.items()):
                        if user_data.get('email') and user_data.get('notify'):
                            with email_send_lock:
                                last_sent_id = user_data.get('last_sent_id', 0)
                                anns_to_send = [ann for ann in announcements if ann['id'] > last_sent_id]

                                if anns_to_send:
                                    for ann in sorted(anns_to_send, key=lambda x: x['id']):
                                        ann_id = ann['id']
                                        send_key = f"{user_id}_{ann_id}"

                                        if send_key in last_send_time and (current_time - last_send_time[send_key]) < 300:
                                            continue
                                        if failed_attempts.get(send_key, 0) >= 3:
                                            continue

                                        subject = f"新公告通知: {ann['title']}"
                                        content = f"{ann['content']}\n\n查看详情: http://ann.nki.pw/announcements/{ann_id}"
                                        last_send_time[send_key] = current_time

                                        if send_email(user_data['email'], subject, content):
                                            user_data['last_sent_id'] = ann_id
                                            users[user_id] = user_data
                                            save_users(users)
                                            failed_attempts.pop(send_key, None)
                                            logger.info(f"成功发送公告 #{ann_id} 给: {user_data['email']}")
                                            time.sleep(1)
                                        else:
                                            failed_attempts[send_key] = failed_attempts.get(send_key, 0) + 1
                                            logger.error(f"发送公告 #{ann_id} 失败给: {user_data['email']}，失败次数: {failed_attempts[send_key]}")
                                            break

                    # 清理过期记录
                    expired_keys = [key for key, ts in last_send_time.items() if current_time - ts > 3600]
                    for key in expired_keys:
                        last_send_time.pop(key, None)
                        failed_attempts.pop(key, None)

        except Exception as e:
            logger.error(f"邮件发送线程错误: {e}", exc_info=True)

        time.sleep(30)

# 启动线程
if __name__ == '__main__':
    if not os.path.exists('./flask_session'):
        os.makedirs('./flask_session')

    email_thread = threading.Thread(target=email_sender, daemon=True)
    email_thread.start()
    logger.debug(f"邮件发送线程已启动 [PID: {os.getpid()}, TID: {threading.get_ident()}]")

    app.run(debug=True, port=5001)
