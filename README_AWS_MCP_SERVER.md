
# 🚀 AWS MCP Server

The **Model Context Protocol (MCP)** server is a powerful framework designed to simplify cloud application deployment by leveraging **context-aware infrastructure automation** using native AWS services.

---

## 🔧 Features

- ✅ Context-driven deployment (team, env, region)
- ⚙️ Auto-scaling with smart defaults
- ☁️ Native AWS integration (EC2, Lambda, ECS, RDS, S3, EKS)
- 🔄 CI/CD support with CodePipeline, CodeBuild, CodeDeploy
- 💰 Cost optimization via AWS Cost Explorer
- 🔐 IAM & KMS integrated for secure deployments
- 📄 YAML-based manifest system

---

## 📦 Supported AWS Services

### 🖥️ Compute
- EC2
- Lambda

### 📦 Containers
- ECS
- EKS
- ECR

### 🗄️ Storage & Databases
- S3
- RDS

### 🔐 Identity & Security
- IAM
- KMS
- ACM

### 🔧 CI/CD
- CodePipeline
- CodeBuild
- CodeDeploy
- CodeCommit

### 📊 Monitoring & Billing
- CloudWatch
- CloudWatch Logs
- Cost Explorer
- Organizations
- Tags & Resource Groups

---

## 🧠 Why MCP?

| Feature                | Traditional API | MCP |
|------------------------|----------------|-----|
| Declarative            | ❌              | ✅  |
| Context-Aware          | ❌              | ✅  |
| Secure by Default      | ❌              | ✅  |
| Cost-Aware             | ❌              | ✅  |
| Pluggable Deployments  | ❌              | ✅  |

---

## 🚀 Get Started

### 1. Clone the Repo

```bash
git clone https://github.com/yourname/aws-mcp-server.git
cd aws-mcp-server
```

### 2. Install `uv`

```bash
pip install uv
```

### 3. Install Project Requirements

```bash
uv pip install -r requirements.txt
```

### 4. Install GitHub Copilot Chat

- Open VS Code
- Go to **Extensions → GitHub Copilot Chat → Install**

---

## 🖥️ VS Code Configuration

Open VS Code Command Palette with `Ctrl+Shift+P`, then:

- Search for: `Preferences: Open User Settings (JSON)`
- Paste and edit the following:

```json
{
  "mcp": {
    "servers": {
      "aws": {
        "command": "uv",
        "args": [
          "run",
          "--with",
          "mcp[cli],boto3",
          "mcp",
          "run",
          "D:\\Dileep\\MCPAws\\awsmcp\\main.py"
        ]
      }
    }
  },
  "files.autoSave": "afterDelay"
}
```

---

## 🆕 Creating a New MCP Server

### Step-by-step Guide:

```bash
# 1. Install GitHub Copilot Chat Extension (VS Code)
# 2. Install uv package manager
pip install uv

# 3. Initialize a new MCP project
uv init my-first-mcp-server
cd my-first-mcp-server

# 4. Add MCP CLI to your project
uv add "mcp[cli]"

# 5. (Optional) Fix any typer type errors
pip install --upgrade typer
```

### 6. Write code in `main.py`

Example:
```python
from mcp import App, Context

app = App(name="aws-mcp-server")

@app.task()
def deploy(ctx: Context):
    print(f"Deploying to {ctx.env} in region {ctx.region}")
```

### 7. Update VS Code `settings.json`

```json
{
  "mcp": {
    "servers": {
      "aws": {
        "command": "uv",
        "args": [
          "run",
          "--with",
          "mcp[cli],boto3",
          "mcp",
          "run",
          "D:\\Dileep\\MCPAws\\awsmcp\\main.py"
        ]
      }
    }
  },
  "files.autoSave": "afterDelay"
}
```

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

---

## 📬 Contact

**Author:** Dileep  
📧 Email: dileep@example.com  
🔗 LinkedIn: [https://linkedin.com/in/your-profile](https://linkedin.com/in/your-profile)

---

## 🏷️ Tags

```
#AWS #MCP #ModelContextProtocol #DevOps #CloudAutomation
#GitHubCopilot #Python #uv #IaC #CloudNative
```

---

> MCP makes your AWS deployments **smarter, faster, and context-aware.** 🎯
