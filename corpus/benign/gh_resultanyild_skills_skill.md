---
name: placeholder-image
version: "1.0"
description: Download random placeholder images from Lorem Picsum. Use when user asks for placeholder images, needs sample images ...
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: resultanyildizi/skills
# corpus-url: https://github.com/resultanyildizi/skills/blob/HEAD/placeholder-image/skill.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# Placeholder Image Downloader

Download random images from Lorem Picsum (picsum.photos) for use as placeholders in projects.

## Usage

When invoked, download placeholder images using the helper script.

### Arguments (all optional)

- `count`: Number of images to download (default: 1)
- `--size WxH`: Image dimensions, e.g., `1920x1080` (default: `800x600`, max: `5000x5000`)
- `--hd`: 1280x720 (720p)
- `--fhd` or `--1080p`: 1920x1080 (Full HD)
- `--2k`: 2560x1440 (QHD)
- `--4k`: 3840x2160 (Ultra HD)
- `--5k` or `--max`: 5000x5000 (maximum resolution)
- `--grayscale`: Download grayscale images
- `--blur N`: Apply blur effect (1-10)
- `--output DIR`: Download directory (default: current working directory)

### Examples

```bash
# Download 1 image to current directory
~/.claude/skills/placeholder-image/scripts/download.sh

# Download 3 Full HD images to ./assets
~/.claude/skills/placeholder-image/scripts/download.sh 3 --fhd --output ./assets

# Download a 4K image
~/.claude/skills/placeholder-image/scripts/download.sh --4k

# Download 2 grayscale images at max resolution
~/.claude/skills/placeholder-image/scripts/download.sh 2 --5k --grayscale

# Download blurred images
~/.claude/skills/placeholder-image/scripts/download.sh 2 --blur 5
```

## Behavior

1. Parse the user's request to determine count, size, effects, and output directory
2. Run the download script with appropriate arguments
3. Report the downloaded file paths to the user
4. If downloading for a specific frontend task, suggest how to use the images in the code

## Image Naming

Images are saved as `placeholder-{timestamp}-{index}.jpg` to avoid conflicts.