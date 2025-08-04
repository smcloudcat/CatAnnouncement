# OAuth配置参数
CLIENT_ID = 'CatAnnouncement'
REDIRECT_URI = 'http://ann.nki.pw/callback'  # 本地开发回调地址

# 授权服务器端点URL
AUTHORIZATION_ENDPOINT = 'https://oauth.lwcat.cn/oauth/authorize'
TOKEN_ENDPOINT = 'https://oauth.lwcat.cn/oauth/token'
USERINFO_ENDPOINT = 'https://oauth.lwcat.cn/api/me'

# 请求的权限范围
SCOPE = 'profile email avatar username'

# 管理员配置
SUPER_ADMIN_EMAIL = '3522934828@qq.com'  # 总管理员邮箱

# 邮件配置
MAIL_SERVER = 'smtp.163.com'
MAIL_PORT = 465
MAIL_USE_SSL = True
MAIL_USERNAME = 'xiccsend@163.com'
MAIL_PASSWORD = '123456'
MAIL_DEFAULT_SENDER = ('CatOauth用户中心', 'xiccsend@163.com')
