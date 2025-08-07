from flask import Flask, session, redirect, url_for, request, render_template, jsonify, abort
from flask_session import Session
import requests
import os
import json
import time
import threading
import smtplib
import logging
import fcntl  # 用于文件锁（Linux/Unix）
from email.mime.text import MIMEText
from datetime import datetime
from config import CLIENT_ID, REDIRECT_URI, AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, USERINFO_ENDPOINT, SCOPE, SUPER_ADMIN_EMAIL, MAIL_SERVER, MAIL_PORT, MAIL_USE_SSL, MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER

app = Flask(__name__)
app.secret_key = os.urandom(24)

# 配置服务器端会话
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session'
Session(app)

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# File locks to prevent race conditions
user_lock = threading.Lock()
announcements_lock = threading.Lock()
admins_lock = threading.Lock()

# 文件锁路径
LOCK_FILE = "./email_sender.lock"

# 加载公告数据
def load_announcements():
    with announcements_lock:
        try:
            with open('announcements.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

# 保存公告数据
def save_announcements(announcements):
    with announcements_lock:
        with open('announcements.json', 'w', encoding='utf-8') as f:
            json.dump(announcements, f, ensure_ascii=False, indent=2)

# 加载用户数据
def load_users():
    with user_lock:
        try:
            with open('users.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

# 保存用户数据
def save_users(users):
    with user_lock:
        with open('users.json', 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)

# 加载管理员数据
def load_admins():
    with admins_lock:
        try:
            with open('admins.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return [SUPER_ADMIN_EMAIL]

# 保存管理员数据
def save_admins(admins):
    with admins_lock:
        with open('admins.json', 'w', encoding='utf-8') as f:
            json.dump(admins, f, ensure_ascii=False, indent=2)

# 检查用户是否为管理员
def is_admin(user_email):
    admins = load_admins()
    return user_email in admins

# 发送邮件
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

# 邮件发送状态跟踪
email_send_lock = threading.Lock()
last_send_time = {}
failed_attempts = {}

# 文件锁获取和释放
def acquire_file_lock():
    lock_file = open(LOCK_FILE, 'w')
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return lock_file
    except (IOError, BlockingIOError):
        lock_file.close()
        return None

def release_file_lock(lock_file):
    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    lock_file.close()

# 邮件发送线程
def email_sender():
    global last_send_time, failed_attempts
    while True:
        lock_file = acquire_file_lock()
        if lock_file is None:
            logger.debug(f"无法获取文件锁，跳过本次邮件发送检查 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
            time.sleep(30)
            continue

        try:
            users = load_users()
            announcements = load_announcements()
            
            if announcements and users:
                current_time = time.time()
                
                for user_id, user_data in list(users.items()):
                    if user_data.get('email') and user_data.get('notify'):
                        with email_send_lock:  # 线程锁保护
                            last_sent_id = user_data.get('last_sent_id', 0)
                            anns_to_send = [ann for ann in announcements if ann['id'] > last_sent_id]
                            
                            if anns_to_send:
                                for ann in sorted(anns_to_send, key=lambda x: x['id']):
                                    ann_id = ann['id']
                                    send_key = f"{user_id}_{ann_id}"
                                    
                                    if send_key in last_send_time and (current_time - last_send_time[send_key]) < 300:
                                        logger.debug(f"跳过公告 #{ann_id} 给 {user_data['email']}，5分钟内已尝试 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
                                        continue
                                    
                                    if failed_attempts.get(send_key, 0) >= 3:
                                        logger.warning(f"公告 #{ann_id} 给 {user_data['email']} 发送失败次数已达上限 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
                                        continue
                                    
                                    subject = f"新公告通知: {ann['title']}"
                                    content = f"{ann['content']}\n\n查看详情: http://ann.nki.pw/announcements/{ann['id']}"
                                    
                                    logger.debug(f"准备发送公告 #{ann_id} 给 {user_data['email']} [PID: {os.getpid()}, TID: {threading.get_ident()}]")
                                    last_send_time[send_key] = current_time
                                    
                                    if send_email(user_data['email'], subject, content):
                                        user_data['last_sent_id'] = ann_id
                                        users[user_id] = user_data
                                        save_users(users)
                                        logger.info(f"成功发送公告 #{ann_id} 给: {user_data['email']} [PID: {os.getpid()}, TID: {threading.get_ident()}]")
                                        if send_key in failed_attempts:
                                            del failed_attempts[send_key]
                                        time.sleep(1)
                                    else:
                                        failed_attempts[send_key] = failed_attempts.get(send_key, 0) + 1
                                        logger.error(f"发送公告 #{ann_id} 失败给: {user_data['email']}，失败次数: {failed_attempts[send_key]} [PID: {os.getpid()}, TID: {threading.get_ident()}]")
                                        break
                
                expired_keys = [key for key, ts in last_send_time.items() if current_time - ts > 3600]
                for key in expired_keys:
                    del last_send_time[key]
                    if key in failed_attempts:
                        del failed_attempts[key]
                
        except Exception as e:
            logger.error(f"邮件发送线程错误: {e} [PID: {os.getpid()}, TID: {threading.get_ident()}]", exc_info=True)
        finally:
            release_file_lock(lock_file)
        
        time.sleep(30)

# 启动邮件发送线程，仅在获取文件锁的进程中
lock_file = acquire_file_lock()
if lock_file is not None:
    email_thread = threading.Thread(target=email_sender, daemon=True)
    email_thread.start()
    logger.debug(f"邮件发送线程已启动 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
    release_file_lock(lock_file)
else:
    logger.debug(f"非主进程，跳过启动邮件发送线程 [PID: {os.getpid()}, TID: {threading.get_ident()}]")

@app.route('/')
def index():
    logger.debug(f"访问首页 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
    state = os.urandom(16).hex()
    session['oauth2_state'] = state
    
    auth_url = f"{AUTHORIZATION_ENDPOINT}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={state}"
    
    user_info = session.get('user_info')
    admin_flag = False
    if user_info and user_info.get('email'):
        admin_flag = is_admin(user_info['email'])
    
    page = int(request.args.get('page', 1))
    per_page = 10
    
    announcements_list = load_announcements()
    total = len(announcements_list)
    
    start = (page - 1) * per_page
    end = start + per_page
    paginated_anns = announcements_list[::-1][start:end]
    
    return render_template('index.html',
                           authorization_url=auth_url,
                           announcements=paginated_anns,
                           current_page=page,
                           total_pages=(total + per_page - 1) // per_page,
                           user_info=user_info,
                           is_admin=admin_flag)

@app.route('/callback')
def callback():
    logger.debug(f"OAuth回调开始 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
    
    if 'code' not in request.args:
        if 'error' in request.args:
            logger.error(f"授权失败: {request.args.get('error')} - {request.args.get('error_description')} [PID: {os.getpid()}, TID: {threading.get_ident()}]")
            return f"授权失败: {request.args.get('error')} - {request.args.get('error_description')}", 400
        return '未收到授权码(code)。', 400
    
    code = request.args.get('code')
    
    try:
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID
        }
        token_response = requests.post(TOKEN_ENDPOINT, data=token_data, headers={'Accept': 'application/json'})
        token_response.raise_for_status()
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            logger.error(f"响应中未包含access_token [PID: {os.getpid()}, TID: {threading.get_ident()}]")
            return '响应中未包含access_token。', 400
        
        access_token = token_json['access_token']
        
        user_response = requests.get(USERINFO_ENDPOINT, headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        })
        user_response.raise_for_status()
        user_info = user_response.json()
        logger.debug(f"获取到用户信息: {user_info} [PID: {os.getpid()}, TID: {threading.get_ident()}]")
        
        session['user_info'] = user_info
        session['access_token'] = access_token
        session.modified = True
        logger.debug(f"会话已保存: {session} [PID: {os.getpid()}, TID: {threading.get_ident()}]")
        
        users = load_users()
        user_id = user_info['id']
        if user_id not in users:
            announcements = load_announcements()
            latest_ann_id = announcements[-1]['id'] if announcements else 0
            users[user_id] = {'notify': False, 'email': '', 'last_sent_id': latest_ann_id}
            save_users(users)
        
        logger.debug(f"OAuth登录成功，重定向到公告页面 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
        return redirect(url_for('announcements'))
    
    except requests.exceptions.RequestException as e:
        logger.error(f"请求失败: {str(e)} [PID: {os.getpid()}, TID: {threading.get_ident()}]")
        return f'请求失败: {str(e)}', 500

@app.route('/announcements')
def announcements():
    logger.debug(f"访问公告页面 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
    if 'user_info' not in session:
        logger.debug(f"未登录用户访问公告列表 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
        user_info = None
        is_admin_flag = False
    else:
        logger.debug(f"用户已登录: {session['user_info']} [PID: {os.getpid()}, TID: {threading.get_ident()}]")
        user_info = session['user_info']
        is_admin_flag = is_admin(user_info['email'])
    
    page = int(request.args.get('page', 1))
    per_page = 10
    
    announcements_list = load_announcements()
    total = len(announcements_list)
    
    start = (page - 1) * per_page
    end = start + per_page
    paginated_anns = announcements_list[::-1][start:end]
    
    return render_template('index.html',
                          announcements=paginated_anns,
                          current_page=page,
                          total_pages=(total + per_page - 1) // per_page,
                          user_info=user_info,
                          is_admin=is_admin_flag)

@app.route('/announcements/<int:id>')
def announcement_detail(id):
    logger.debug(f"访问公告详情: {id} [PID: {os.getpid()}, TID: {threading.get_ident()}]")
    if 'user_info' not in session:
        logger.debug(f"未登录用户访问公告详情 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
        user_info = None
        is_admin_flag = False
    else:
        user_info = session['user_info']
        is_admin_flag = is_admin(user_info['email'])
    
    announcements_list = load_announcements()
    announcement = next((a for a in announcements_list if a['id'] == id), None)
    
    if not announcement:
        abort(404)
    
    return render_template('announcement_detail.html',
                          announcement=announcement,
                          user_info=user_info,
                          is_admin=is_admin_flag)

@app.route('/admin/announcements', methods=['GET', 'POST'])
def manage_announcements():
    logger.debug(f"访问管理公告页面 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
    if 'user_info' not in session:
        logger.debug(f"用户未登录，重定向到首页 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
        return redirect(url_for('index'))
    
    user_email = session['user_info'].get('email', '')
    if not is_admin(user_email):
        return "无管理权限", 403
    
    announcements_list = load_announcements()
    user_info = session['user_info']
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        if title and content:
            new_id = max([a['id'] for a in announcements_list], default=0) + 1
            new_announcement = {
                'id': new_id,
                'title': title,
                'content': content,
                'created_at': datetime.now().isoformat(),
                'author': user_info['nickname']
            }
            
            announcements_list.append(new_announcement)
            save_announcements(announcements_list)
            
            return redirect(url_for('manage_announcements'))
    
    return render_template('admin_announcements.html',
                          announcements=announcements_list,
                          user_info=user_info,
                          is_admin=True)

@app.route('/admin/announcements/delete/<int:id>')
def delete_announcement(id):
    logger.debug(f"删除公告: {id} [PID: {os.getpid()}, TID: {threading.get_ident()}]")
    if 'user_info' not in session:
        logger.debug(f"用户未登录，重定向到首页 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
        return redirect(url_for('index'))
    
    user_email = session['user_info'].get('email', '')
    if not is_admin(user_email):
        return "无管理权限", 403
    
    announcements_list = load_announcements()
    announcements_list = [a for a in announcements_list if a['id'] != id]
    save_announcements(announcements_list)
    
    return redirect(url_for('manage_announcements'))

@app.route('/settings', methods=['GET', 'POST'])
def user_settings():
    logger.debug(f"访问用户设置页面 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
    if 'user_info' not in session:
        logger.debug(f"用户未登录，重定向到首页 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
        return redirect(url_for('index'))
    
    user_info = session['user_info']
    user_id = user_info['id']
    users = load_users()
    user_data = users.get(user_id, {'notify': False, 'email': '', 'last_sent_id': 0})
    is_admin_flag = is_admin(user_info['email'])
    
    if request.method == 'POST':
        email = request.form.get('email')
        notify = request.form.get('notify') == 'on'
        
        user_data['email'] = email
        user_data['notify'] = notify
        
        users[user_id] = user_data
        save_users(users)
        
        return redirect(url_for('user_settings'))
    
    return render_template('user_settings.html',
                          user_data=user_data,
                          user_info=user_info,
                          is_admin=is_admin_flag)

@app.route('/admin/manage_admins', methods=['GET', 'POST'])
def manage_admins():
    logger.debug(f"访问管理管理员页面 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
    if 'user_info' not in session:
        logger.debug(f"用户未登录，重定向到首页 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
        return redirect(url_for('index'))
    
    user_info = session['user_info']
    user_email = user_info.get('email', '')
    if user_email != SUPER_ADMIN_EMAIL:
        return "无管理权限", 403
    
    admins = load_admins()
    
    if request.method == 'POST':
        action = request.form.get('action')
        email = request.form.get('email')
        
        if action == 'add' and email:
            if email not in admins:
                admins.append(email)
                save_admins(admins)
        elif action == 'remove' and email:
            if email in admins and email != SUPER_ADMIN_EMAIL:
                admins.remove(email)
                save_admins(admins)
        
        return redirect(url_for('manage_admins'))
    
    show_success = request.method == 'POST'
    return render_template('manage_admins.html',
                          admins=admins,
                          super_admin=SUPER_ADMIN_EMAIL,
                          show_success=show_success,
                          user_info=user_info,
                          is_admin=True)

@app.route('/logout')
def logout():
    logger.debug(f"用户注销 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
    session.pop('user_info', None)
    session.pop('access_token', None)
    session.pop('oauth2_state', None)
    session.modified = True
    logger.debug(f"会话已清除 [PID: {os.getpid()}, TID: {threading.get_ident()}]")
    return redirect(url_for('index'))

if __name__ == '__main__':
    if not os.path.exists('./flask_session'):
        os.makedirs('./flask_session')
    
    app.run(debug=True, port=5001)