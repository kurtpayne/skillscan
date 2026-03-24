---
name: multi-provider-media-generation
description: 面向 Codex 的多后端图像与视频生成 skill。用于配置 `novelai_official`、`novelai_compatible`、`nanobanana`、`grok_imagine`，检查能力矩阵，并通过统一的 `media-skill` CLI 执行 `txt2img`、`img2img`、`img2video`。当用户需要在同一 provider 下切换多个模型、在 Windows 上把复制/粘贴的图片直接作为 `nanobanana` 的 `img2img` 输入、为 NovelAI 长期保存常用画师串与负面提示词，或希望把自然语言需求整理成更接近 Danbooru / Donmai 风格的 tag，并按需查询 Donmai wiki 与 API 校对 tag 时使用。
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: huiyiyichen/multi-provider-media-generation
# corpus-url: https://github.com/huiyiyichen/multi-provider-media-generation/blob/537eb10f0f6e1546a489f60a526c16791d58ffbc/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# 多后端图像 / 视频生成

## 工作方式

- 只使用 `media-skill` 作为唯一入口。
- 在当前仓库本地运行时，把 `media-skill ...` 视为 `node dist/cli.js ...`。
- 所有请求都必须先经过 provider 能力解析与字段白名单校验，不要臆测第三方私有字段。

## 操作流程

1. 用 `media-skill config set|get|list|validate` 管理 provider 配置。
2. NovelAI 的小片段预设用 `media-skill preset ...` 管理。
3. NovelAI 的长期常用画师串和负面词，用 `media-skill profile ...` 管理。
4. 不确定某个 `provider + model + operation + request_style` 是否支持时，先运行 `media-skill capabilities`。
5. 用 `media-skill generate` 读取 JSON 输入并执行生成。

## NovelAI 规则

- 如果用户要你“按我平时那套 NAI 负面词和画师串来”，优先使用默认 profile；如果有多个 profile，先 `media-skill profile list` 再选最合适的一个。
- 为 NovelAI 生成提示词时，先把用户自然语言需求改写成简洁的标签串，再调用 `generate`。优先写主体、外观、服装、场景、光影、镜头等标签，不要直接把整段自然语言原样发给 NAI。
- 如果只是复用已保存的 profile，优先使用 `prompt_mode: raw`，把你整理好的标签放进 `prompt`。profile 会自动补上保存的正面画师串和负面词。
- 如果还要叠加 `artist_preset`、`style_preset`、`negative_preset` 等片段，再使用 `prompt_mode: composed`。
- `novelai_compatible` 的 `nai_compatible` 风格按已知规则映射到 `/v1/chat/completions` 形态，请求里会发送 `messages`、`model`、`negative_prompt`、`size/image_size`、`scale`、`steps`、`sampler` 等字段。

## NovelAI 尺寸选择规则

- 默认尺寸策略是 `normal + 1:1`，也就是 `1024:1024`。
- 如果用户明确说“生成小图”、“先来小一点”、“测试图”，优先使用 `small`。
- 如果用户明确说“大图”，优先使用 `large`。
- 如果用户明确说“超大图”、“超高分辨率”、“高清壁纸”、“桌面壁纸”、“手机壁纸”、“wallpaper”，优先使用 `wallpaper`。
- 如果用户没有提尺寸级别，就用 `normal`。
- 长宽比默认按 `1:1` 处理；如果用户明确说“横图”、“横版”、“landscape”，改用横图尺寸；如果用户明确说“竖图”、“竖版”、“portrait”，改用竖图尺寸。
- `wallpaper` 没有正方形尺寸。如果用户只说“超大图”或“壁纸”但没说横竖，优先自行判断：
  - 更像桌面壁纸、场景图、横向构图时，用 `1920:1088`。
  - 更像手机壁纸、人物立绘、竖向构图时，用 `1088:1920`。
- 如果用户自己明确给了尺寸或纵横比要求，始终以用户要求为准。
- 需要具体尺寸表时，读取 [references/novelai-size-policy.md](references/novelai-size-policy.md)。

## Danbooru / Donmai 可选流程

- 当用户明确提到 `Danbooru`、`Donmai`、`wiki`、`tag` 标准名、别名校对，或你怀疑某些画师名、角色名、版权名、冷门 tag 可能写错时，优先按需读取 [references/danbooru-workflow.md](references/danbooru-workflow.md)。
- 默认做法是先把需求整理成适合 NAI 的标签串，再决定是否需要 Donmai 校对；不要为了每一张图都机械地查站。
- 如果本地存在 `data/config/donmai.json`，说明已经保存 Donmai 查询配置。此时：
  - 要查标准 tag 名、分类、热度、别名时，优先用 API。
  - 要看 tag 具体含义、用法、歧义说明时，再看 wiki。
- 如果没有本地 Donmai 配置，就只按你已有知识输出 Danbooru / NAI 风格 tag，不要假装自己已经查过 API。

## 关键规则

- 如果同一个 provider 配置了多个模型，生成输入里要显式传 `model`，且只能从该 provider 的 `allowed_models` 中选择。
- `nanobanana` 走最小输入的 `chat/completions` 适配器，不接受 `negative_prompt`、`width`、`height`、`steps`、`cfg_scale`、`seed` 等被矩阵禁止的字段。
- 当用户在 Windows 上直接复制或粘贴图片，并希望对 `nanobanana` 做 `img2img` 时，优先使用下面这种输入：

```json
{
  "provider": "nanobanana",
  "operation": "img2img",
  "model": "gemini-3.1-flash-image-preview",
  "prompt": "改成夜景霓虹风格",
  "source_image": {
    "type": "clipboard",
    "value": "current"
  }
}
```

- `clipboard` 会读取当前系统剪贴板中的图片；如果是自动化测试或非 Windows 环境，可用环境变量 `MEDIA_SKILL_CLIPBOARD_IMAGE_DATA_URL` 注入 data URL。
- 输出文件直接保存到 `data/runs/YYYY-MM-DD/`，不再为每张图片单独建文件夹，也不再额外生成每张图的 `metadata.json`。

## 结果展示

- 生成成功后，必须同时返回落盘目录和每个资产的绝对路径。优先使用 `display_output_dir` 与每个 asset 的 `display_path`；只有在它们不存在时才退回 `output_dir` 与 `path`。
- 如果结果是图片，并且当前运行环境支持 Markdown 图片渲染，优先直接用绝对路径内嵌图片，不要只给文件路径列表。
- 在 Codex 桌面环境中，应使用 `![说明文字](绝对路径)` 的形式展示本地图片。
- 如果同一轮生成了多张图片，先给出简短的角色或主题说明，再逐张展示图片。
- 只有在图片无法渲染或用户明确只要路径时，才退化为仅返回文件路径。

## 参考文档

- 先看 [README.md](README.md) 获取完整中文使用说明。
- 需要命令语法时看 [references/cli-usage.md](references/cli-usage.md)。
- 需要 JSON 输入示例时看 [references/examples.md](references/examples.md)。
- 需要能力矩阵时看 [references/provider-capabilities.md](references/provider-capabilities.md)。
- 需要按需校对 Danbooru / Donmai tag 时看 [references/danbooru-workflow.md](references/danbooru-workflow.md)。