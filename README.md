# CatOauth Python 示例

这是一个使用Python Flask框架实现的OAuth 2.0客户端示例，演示如何与授权服务器集成实现第三方登录功能。

## 功能特性

- 实现OAuth 2.0授权码流程
- 支持state参数防止CSRF攻击
- 获取用户基本信息（ID、昵称、邮箱、头像）
- 用户信息展示页面
- 退出登录功能

## 快速开始

### 前置条件
- Python 3.7+
- pip 包管理工具

### 安装步骤

1. 克隆仓库：
```bash
git clone https://github.com/smcloudcat/CatOauth-python-Demo.git
cd CatOauth-python-Demo
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

### 运行应用
```bash
python app.py
```

应用将在 http://localhost:5000 启动

## 配置说明

编辑 `config.py` 文件配置OAuth参数：
```python
# 客户端ID（随意）
CLIENT_ID = 'your-client-id'

# 回调地址
REDIRECT_URI = 'http://your-domain/callback'

# 授权服务器端点
AUTHORIZATION_ENDPOINT = 'https://oauth.lwcat.cn/oauth/authorize'
TOKEN_ENDPOINT = 'https://oauth.lwcat.cn/oauth/token'
USERINFO_ENDPOINT = 'https://oauth.lwcat.cn/api/me'

# 请求的权限范围
SCOPE = 'profile email avatar username'
```

## 项目结构
```
CatOauth-python-Demo/
├── app.py              # 主应用文件
├── config.py           # 配置文件
├── requirements.txt    # 依赖列表
└── templates/          # 模板文件
    ├── index.html      # 登录页面
    └── user_info.html  # 用户信息页面
```

## 使用流程

1. 访问 http://localhost:5000
2. 点击"使用授权平台登录"按钮
3. 授权后跳转回应用
4. 查看用户信息
5. 可点击"退出登录"返回首页

## 贡献指南

欢迎提交Issue和Pull Request。请确保代码符合PEP8规范并通过基本测试。

## 许可证

本项目采用MIT许可证。详见LICENSE文件。
