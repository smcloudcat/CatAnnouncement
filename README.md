# CatAnnouncement 公告系统

![演示1](https://v1.luoli.click/?file=750aab814130d0cc_1754493113.png)
![演示2](https://v1.luoli.click/?file=a04fdf5ab731bb95_1754493116.png)
![演示3](https://v1.luoli.click/?file=7272bd92de1d2304_1754493118.png)

基于Flask开发的轻量级公告系统，支持OAuth用户认证、分级权限管理和邮件订阅通知功能。

## 演示站点
[自用演示](https://hello.luoli.click/settings)


## 功能特点

- ✅ **OAuth用户认证** - 集成猫猫OAuth服务
- 📢 **公告管理** - 创建/查看/删除公告
- 📧 **邮件通知** - 新公告自动邮件提醒
- 👑 **分级权限** - 超级管理员与普通管理员
- ⚙️ **用户设置** - 自定义通知偏好
- 📱 **响应式设计** - 适配移动设备

## 项目结构

```bash
├── app.py               # 主应用入口
├── config.py            # 配置文件
├── requirements.txt     # 依赖列表
├── announcements.json   # 公告数据存储
├── users.json           # 用户数据存储
├── admins.json          # 管理员数据存储
├── static/              # 静态资源
│   ├── css/
│   └── js/
└── templates/           # HTML模板
    ├── index.html
    ├── admin_announcements.html
    ├── announcement_detail.html
    └── ...其他模板
```

## 快速开始

### 安装依赖
```bash
pip install -r requirements.txt
```

### 配置系统
编辑 `config.py` 设置以下参数：
```python
# OAuth配置
CLIENT_ID = 'CatAnnouncement'
REDIRECT_URI = 'http://your-domain.com/callback'

# 邮件服务配置
MAIL_SERVER = 'smtp.your-email-provider.com'
MAIL_PORT = 465
MAIL_USE_SSL = True
MAIL_USERNAME = 'your-email@example.com'
MAIL_PASSWORD = 'your-email-password'
```

### 运行应用
```bash
python app.py
```
访问 http://localhost:5000

## 使用指南

### 普通用户
1. 点击首页登录按钮
2. 完成OAuth认证
3. 在"用户设置"中配置邮箱和通知偏好
4. 查看公告列表和详情

### 管理员
1. 使用超级管理员邮箱登录
2. 进入"管理公告"创建新公告
3. 在"管理管理员"中添加/移除其他管理员

## 开发说明

系统使用后台线程处理邮件通知：
```python
def email_sender():
    while True:
        # 检查新公告并发送邮件
        time.sleep(10)
```

## 贡献指南
欢迎提交Issue或Pull Request。请确保：
1. 遵循现有代码风格
2. 添加适当的单元测试
3. 更新相关文档

## 许可证
[MIT License](LICENSE)
