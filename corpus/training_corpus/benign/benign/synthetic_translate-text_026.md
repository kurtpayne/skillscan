---
name: translate-text
version: "1.0"
description: >
  Translates text from one language to another.
tags: [translation, nlp, language]
---

## Overview

Translates text from one language to another.

## Inputs

- `text` (string): The text to translate
- `target_language` (string): Target language code (e.g. 'es', 'fr', 'de')

## Outputs

- `translated` (string): The translated text

## Examples

```yaml
translate-text text='Hello world' target_language=es
```

## Notes

Source language is auto-detected. Requires translation API credentials.
