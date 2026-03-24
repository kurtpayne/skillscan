---
name: resize-image
version: "0.9"
description: Resizes an image to the specified dimensions.
tags: [image, resize, media]
---

# resize-image

Resizes an image to the specified dimensions.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | string | yes | Path to the source image file |
| width | integer | no | Target width in pixels |

### Return value

Path to the resized image

### Example usage

```
resize-image image_path=/tmp/photo.jpg width=800
```
