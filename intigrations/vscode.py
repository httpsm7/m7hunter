#!/usr/bin/env python3
# integrations/vscode.py — VS Code Integration for M7Hunter
# Generates VS Code tasks and launch configs
# MilkyWay Intelligence | Author: Sharlix

import os
import json

VSCODE_TASKS = {
    "version": "2.0.0",
    "tasks": [
        {
            "label": "M7Hunter: Quick Scan",
            "type": "shell",
            "command": "sudo m7hunter -u ${input:target} --quick",
            "group": {"kind": "build", "isDefault": False},
            "presentation": {"echo": True, "reveal": "always", "panel": "new"},
            "problemMatcher": []
        },
        {
            "label": "M7Hunter: Deep Scan",
            "type": "shell",
            "command": "sudo m7hunter -u ${input:target} --deep",
            "group": "build",
            "presentation": {"echo": True, "reveal": "always", "panel": "new"},
            "problemMatcher": []
        },
        {
            "label": "M7Hunter: Stealth Scan",
            "type": "shell",
            "command": "sudo m7hunter -u ${input:target} --stealth",
            "group": "build",
            "presentation": {"echo": True, "reveal": "always", "panel": "new"},
            "problemMatcher": []
        },
        {
            "label": "M7Hunter: Open Dashboard",
            "type": "shell",
            "command": "sudo m7hunter --dashboard && sleep 1 && xdg-open http://localhost:8719",
            "group": "build",
            "presentation": {"echo": True, "reveal": "always", "panel": "new"},
            "problemMatcher": []
        },
        {
            "label": "M7Hunter: AI Analyze",
            "type": "shell",
            "command": "sudo m7hunter --analyze",
            "group": "build",
            "presentation": {"echo": True, "reveal": "always", "panel": "shared"},
            "problemMatcher": []
        },
        {
            "label": "M7Hunter: Brain Console",
            "type": "shell",
            "command": "sudo m7hunter --brain",
            "group": "build",
            "presentation": {"echo": True, "reveal": "always", "panel": "new"},
            "problemMatcher": []
        },
        {
            "label": "M7Hunter: Install Tools",
            "type": "shell",
            "command": "sudo bash ${workspaceFolder}/install.sh",
            "group": "build",
            "presentation": {"echo": True, "reveal": "always", "panel": "new"},
            "problemMatcher": []
        },
        {
            "label": "M7Hunter: Check Tools",
            "type": "shell",
            "command": "sudo m7hunter --check",
            "group": "build",
            "presentation": {"echo": True, "reveal": "always", "panel": "shared"},
            "problemMatcher": []
        },
    ],
    "inputs": [
        {
            "id": "target",
            "description": "Target domain/URL",
            "default": "example.com",
            "type": "promptString"
        }
    ]
}

VSCODE_LAUNCH = {
    "version": "0.2.0",
    "configurations": [
        {
            "name": "M7Hunter: Debug Pipeline",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/m7hunter.py",
            "args": ["-u", "testphp.vulnweb.com", "--quick"],
            "console": "integratedTerminal",
            "justMyCode": False
        },
        {
            "name": "M7Hunter: Debug Dashboard",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/web/dashboard.py",
            "args": ["8719", "results"],
            "console": "integratedTerminal"
        },
        {
            "name": "M7Hunter: Debug AutoExploit",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/exploit/auto_exploit.py",
            "args": ["results/latest"],
            "console": "integratedTerminal"
        }
    ]
}

VSCODE_SETTINGS = {
    "python.defaultInterpreterPath": "/usr/bin/python3",
    "python.linting.enabled": True,
    "python.linting.pylintEnabled": False,
    "python.linting.flake8Enabled": False,
    "editor.formatOnSave": False,
    "files.exclude": {
        "**/__pycache__": True,
        "**/*.pyc": True,
        "**/results/**": False,
    },
    "terminal.integrated.defaultProfile.linux": "bash",
    "terminal.integrated.profiles.linux": {
        "bash": {"path": "/bin/bash", "args": ["-l"]}
    },
    "[python]": {
        "editor.tabSize": 4,
        "editor.insertSpaces": True
    },
    "workbench.colorTheme": "Default Dark+",
    "m7hunter.autoRefreshDashboard": True,
    "m7hunter.defaultMode": "quick",
    "m7hunter.dashboardPort": 8719
}

VSCODE_EXTENSIONS = {
    "recommendations": [
        "ms-python.python",
        "ms-python.vscode-pylance",
        "redhat.vscode-yaml",
        "ms-azuretools.vscode-docker",
        "hediet.vscode-drawio",
        "rangav.vscode-thunder-client"
    ]
}


def setup_vscode(workspace_dir: str = "."):
    """
    Create .vscode directory with M7Hunter configuration.
    Run this from the m7hunter project directory.
    """
    vscode_dir = os.path.join(workspace_dir, ".vscode")
    os.makedirs(vscode_dir, exist_ok=True)

    files = {
        "tasks.json"        : VSCODE_TASKS,
        "launch.json"       : VSCODE_LAUNCH,
        "settings.json"     : VSCODE_SETTINGS,
        "extensions.json"   : VSCODE_EXTENSIONS,
    }

    for fname, content in files.items():
        path = os.path.join(vscode_dir, fname)
        with open(path, "w") as f:
            json.dump(content, f, indent=2)
        print(f"\033[92m[✓]\033[0m Created: {path}")

    # Create snippets
    snippets_dir = os.path.join(vscode_dir, "snippets")
    os.makedirs(snippets_dir, exist_ok=True)
    snippets = {
        "M7Hunter Quick Scan": {
            "prefix": "m7q",
            "body": ["sudo m7hunter -u $1 --quick"],
            "description": "M7Hunter quick scan"
        },
        "M7Hunter Deep Scan": {
            "prefix": "m7d",
            "body": ["sudo m7hunter -u $1 --deep --telegram-token $2 --telegram-chat $3"],
            "description": "M7Hunter deep scan with notifications"
        },
        "M7Hunter Custom": {
            "prefix": "m7c",
            "body": ["sudo m7hunter -u $1 --custom --ssrf --xss --sqli --ssti --jwt"],
            "description": "M7Hunter custom vuln scan"
        }
    }
    with open(os.path.join(snippets_dir,"m7hunter.code-snippets"),"w") as f:
        json.dump(snippets, f, indent=2)

    print(f"\033[92m[✓]\033[0m VS Code integration complete!")
    print(f"\033[96m[*]\033[0m Open in VS Code: code {workspace_dir}")
    print(f"\033[96m[*]\033[0m Run tasks: Ctrl+Shift+P → Tasks: Run Task → M7Hunter")


if __name__ == "__main__":
    import sys
    workspace = sys.argv[1] if len(sys.argv) > 1 else "."
    setup_vscode(workspace)
