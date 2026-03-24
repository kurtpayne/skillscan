---
name: resize-image
version: "1.0"
description: >
  Resizes an image to the specified dimensions.
tags: [image, resize, media]
---

## Overview

Resizes an image to the specified dimensions.

## Inputs

- `image_path` (string): Path to the source image file
- `width` (integer): Target width in pixels

## Outputs

- `output_path` (string): Path to the resized image

## Examples

```yaml
resize-image image_path=/tmp/photo.jpg width=800
```

## Notes

Maintains aspect ratio by default. Supports JPEG, PNG, and WebP.
