---
name: translate-text
version: "0.9"
description: Translates text from one language to another.
tags: [translation, nlp, language]
---

# translate-text

Translates text from one language to another.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| text | string | yes | The text to translate |
| target_language | string | no | Target language code (e.g. 'es', 'fr', 'de') |

### Return value

The translated text

### Example usage

```
translate-text text='Hello world' target_language=es
```
