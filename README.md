<<<<<<< HEAD
# AWS MCP Server

[![CI/CD Pipeline](../../actions/workflows/ci-cd.yml/badge.svg)](../../actions/workflows/ci-cd.yml)

A Model Context Protocol (MCP) server for managing AWS resources. This server provides tools for:

- Managing EC2 instances
- Analyzing AWS account status
- Cost optimization and billing analysis
- Account information retrieval

## Features

- Create and manage EC2 instances
- Monitor AWS spending
- Get account creation date and type
- Smart cost optimization suggestions

## Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd awsmcp

# Install dependencies using uv
uv pip install -e .
```

## Development

### Setup Development Environment

```bash
# Install development dependencies
uv pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

### Code Quality

```bash
# Format code
black .

# Run linter
flake8
```

## CI/CD Pipeline

The project includes a GitHub Actions workflow that:
1. Runs tests on Python 3.13
2. Checks code formatting with Black
3. Runs linting with flake8
4. Executes tests with pytest and collects coverage
5. Deploys to AWS (on main branch)

## Environment Variables

Required AWS credentials:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION` (defaults to us-east-1)
=======
# AWS_MCP_Server
>>>>>>> aed5dbb2fc5216093009b523111a61c4a6a674e1
