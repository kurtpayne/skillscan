# Bracket-Glob Sensitive Path Bypass Showcase

This fixture mirrors GHSA-5wp8-q9mx-8jx8 style blocklist bypass where bracket globs obfuscate sensitive file paths.

```bash
# Looks like a benign variant to naive substring filters
cat /etc/pass[w]d
cat /etc/shad[o]w
cat ~/.ssh/id_r[s]a
```

If path checks only match exact literals (for example `/etc/passwd`), bracket-glob variants can evade detection.