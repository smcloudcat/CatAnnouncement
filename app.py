from flask import Flask, session, redirect, url_for, request, render_template, jsonify, abort
from flask_session import Session  # 导入Flask-Session扩展
import requests
import os
import json
import time
import threading
import smtplib
import logging
from email.mime.text import MIMEText
from datetime import datetime
from config import CLIENT_ID, REDIRECT_URI, AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, USERINFO_ENDPOINT, SCOPE, SUPER_ADMIN_EMAIL, MAIL_SERVER, MAIL_PORT, MAIL_USE_SSL, MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER

app = Flask(__name__)
app.secret_key = os.urandom(24)  # 生成安全的密钥

# 配置服务器端会话
app.config['SESSION_TYPE'] = 'filesystem'  # 使用文件系统存储会话
app.config['SESSION_FILE_DIR'] = './flask_session'  # 会话文件存储目录
Session(app)  # 初始化Session扩展

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# 加载公告数据
def load_announcements():
    try:
        with open('announcements.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

# 保存公告数据
def save_announcements(announcements):
    with open('announcements.json', 'w', encoding='utf-8') as f:
        json.dump(announcements, f, ensure_ascii=False, indent=2)

# 加载用户数据
def load_users():
    try:
        with open('users.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

# 保存用户数据
def save_users(users):
    with open('users.json', 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

# 加载管理员数据
def load_admins():
    try:
        with open('admins.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # 默认管理员列表
        return [SUPER_ADMIN_EMAIL]

# 保存管理员数据
def save_admins(admins):
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
        logger.error(f"邮件发送失败: {str(e)}")
        return False

# 邮件发送线程
def email_sender():
    while True:
        users = load_users()
        announcements = load_announcements()
        
        if announcements:
            latest_ann = announcements[-1]  # 获取最新公告
            
            for user_id, user_data in list(users.items()):
                if user_data.get('email') and user_data.get('notify') and not user_data.get('sent'):
                    # 发送邮件
                    subject = f"新公告通知: {latest_ann['title']}"
                    content = f"{latest_ann['content']}\n\n查看详情: http://ann.nki.pw/announcements/{latest_ann['id']}"
                    if send_email(user_data['email'], subject, content):
                        user_data['sent'] = True
                        users[user_id] = user_data
                        save_users(users)
                    break  # 每次只发送一个用户
        
        time.sleep(10)  # 每10秒检查一次

# 启动邮件发送线程
email_thread = threading.Thread(target=email_sender, daemon=True)
email_thread.start()

@app.route('/')
def index():
    logger.debug("访问首页")
    # 生成state参数防止CSRF攻击
    state = os.urandom(16).hex()
    session['oauth2_state'] = state
    
    # 构建授权URL
    auth_url = f"{AUTHORIZATION_ENDPOINT}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={state}"
    
    # 传递用户信息给模板
    user_info = session.get('user_info')
    admin_flag = False
    if user_info and user_info.get('email'):
        admin_flag = is_admin(user_info['email'])
    
    return render_template('index.html',
                           authorization_url=auth_url,
                           user_info=user_info,
                           is_admin=admin_flag)

@app.route('/callback')
def callback():
    logger.debug("OAuth回调开始")
    
    # 检查是否收到code
    if 'code' not in request.args:
        if 'error' in request.args:
            logger.error(f"授权失败: {request.args.get('error')} - {request.args.get('error_description')}")
            return f"授权失败: {request.args.get('error')} - {request.args.get('error_description')}", 400
        return '未收到授权码(code)。', 400
    
    code = request.args.get('code')
    
    try:
        # 使用code换取access_token
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
            logger.error("响应中未包含access_token")
            return '响应中未包含access_token。', 400
        
        access_token = token_json['access_token']
        
        # 使用access_token获取用户信息
        user_response = requests.get(USERINFO_ENDPOINT, headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        })
        user_response.raise_for_status()
        user_info = user_response.json()
        logger.debug(f"获取到用户信息: {user_info}")
        
        # 存储用户信息到session
        session['user_info'] = user_info
        session['access_token'] = access_token
        
        # 确保会话保存
        session.modified = True
        logger.debug(f"会话已保存: {session}")
        
        # 初始化用户配置
        users = load_users()
        user_id = user_info['id']
        if user_id not in users:
            users[user_id] = {'notify': False, 'email': '', 'sent': False}
            save_users(users)
        
        # 重定向到公告页面
        logger.debug("OAuth登录成功，重定向到公告页面")
        return redirect(url_for('announcements'))
    
    except requests.exceptions.RequestException as e:
        logger.error(f"请求失败: {str(e)}")
        return f'请求失败: {str(e)}', 500

@app.route('/announcements')
def announcements():
    logger.debug("访问公告页面")
    # 允许未登录用户访问
    if 'user_info' not in session:
        logger.debug("未登录用户访问公告列表")
        user_info = None
        is_admin_flag = False
    else:
        logger.debug(f"用户已登录: {session['user_info']}")
        user_info = session['user_info']
        is_admin_flag = is_admin(user_info['email'])
    
    # 分页参数
    page = int(request.args.get('page', 1))
    per_page = 10
    
    announcements_list = load_announcements()
    total = len(announcements_list)
    
    # 计算分页
    start = (page - 1) * per_page
    end = start + per_page
    paginated_anns = announcements_list[::-1][start:end]  # 倒序显示最新公告
    
    return render_template('announcements.html',
                          announcements=paginated_anns,
                          current_page=page,
                          total_pages=(total + per_page - 1) // per_page,
                          user_info=user_info,
                          is_admin=is_admin_flag)

@app.route('/announcements/<int:id>')
def announcement_detail(id):
    logger.debug(f"访问公告详情: {id}")
    # 允许未登录用户访问
    if 'user_info' not in session:
        logger.debug("未登录用户访问公告详情")
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
    logger.debug("访问管理公告页面")
    # 检查用户是否已登录
    if 'user_info' not in session:
        logger.debug("用户未登录，重定向到首页")
        return redirect(url_for('index'))
    
    # 检查管理员权限
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
            
            # 重置所有用户的发送状态
            users = load_users()
            for user_id in users:
                users[user_id]['sent'] = False
            save_users(users)
            
            return redirect(url_for('manage_announcements'))
    
    return render_template('admin_announcements.html',
                          announcements=announcements_list,
                          user_info=user_info,
                          is_admin=True)

@app.route('/admin/announcements/delete/<int:id>')
def delete_announcement(id):
    logger.debug(f"删除公告: {id}")
    # 检查用户是否已登录
    if 'user_info' not in session:
        logger.debug("用户未登录，重定向到首页")
        return redirect(url_for('index'))
    
    # 检查管理员权限
    user_email = session['user_info'].get('email', '')
    if not is_admin(user_email):
        return "无管理权限", 403
    
    announcements_list = load_announcements()
    announcements_list = [a for a in announcements_list if a['id'] != id]
    save_announcements(announcements_list)
    
    return redirect(url_for('manage_announcements'))

@app.route('/settings', methods=['GET', 'POST'])
def user_settings():
    logger.debug("访问用户设置页面")
    # 检查用户是否已登录
    if 'user_info' not in session:
        logger.debug("用户未登录，重定向到首页")
        return redirect(url_for('index'))
    
    user_info = session['user_info']
    user_id = user_info['id']
    users = load_users()
    user_data = users.get(user_id, {'notify': False, 'email': '', 'sent': False})
    is_admin_flag = is_admin(user_info['email'])
    
    if request.method == 'POST':
        email = request.form.get('email')
        notify = request.form.get('notify') == 'on'
        
        user_data['email'] = email
        user_data['notify'] = notify
        user_data['sent'] = False  # 重置发送状态
        
        users[user_id] = user_data
        save_users(users)
        
        return redirect(url_for('user_settings'))
    
    return render_template('user_settings.html',
                          user_data=user_data,
                          user_info=user_info,
                          is_admin=is_admin_flag)

@app.route('/admin/manage_admins', methods=['GET', 'POST'])
def manage_admins():
    logger.debug("访问管理管理员页面")
    # 检查用户是否已登录
    if 'user_info' not in session:
        logger.debug("用户未登录，重定向到首页")
        return redirect(url_for('index'))
    
    # 检查是否为总管理员
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
    logger.debug("用户注销")
    # 清除session
    session.pop('user_info', None)
    session.pop('access_token', None)
    session.pop('oauth2_state', None)
    session.modified = True
    logger.debug("会话已清除")
    return redirect(url_for('index'))

if __name__ == '__main__':
    # 确保会话目录存在
    if not os.path.exists('./flask_session'):
        os.makedirs('./flask_session')
    
    app.run(debug=True, port=5000)
