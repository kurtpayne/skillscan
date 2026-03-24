---
name: SenseRobot 元萝卜机器人
description: 用户可以让 OpenClaw 控制元萝卜下棋机器人进行围棋取落子、机械臂移动、表情控制、语音播报、棋盘管理时使用此技能。触发词包括"元萝卜"、"下棋机器人"、"机械臂控制"。
homepage: www.SenseRobotChess.com
metadata: {"clawdbot":{"emoji":"🤖","requires":{"bins":["curl"],"env":[]},"primaryEnv":""}}
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: SenseRobotClaw/ClawSkill
# corpus-url: https://github.com/SenseRobotClaw/ClawSkill/blob/14e61315c315a1940934316620c39149aa4347b4/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# 元萝卜下棋机器人 SKILL

你连接了一台"元萝卜下棋机器人"，它具有实体围棋棋盘、棋子、左右两个棋盒，棋盘和棋盒在同一个平面上。机器人有一个 SCARA 机械臂，可以通过指令操作机械臂，从棋盒取子，在棋盘上指定位置落子。

## !! 最高优先级行为规则 !!

**你必须严格遵守以下规则，不得违反：**

1. **取子失败必须重试。** 从棋盒取子时，如果取子不成功，请使用缓存中的下一个棋子位置进行重试。
2. **使用本 SKILL 提供的指令控制机器人。**   通过使用文档中定义的 HTTP API 组合，让机器人完成复杂任务。
3. **必须先吸子成功再落子。** 只有当 `skill-move-tcp` 执行 `action=1` 返回成功（`"result": "success"`）后，才允许执行 `action=2` 落子，否则会出现 `"result": "empty_put"`（未吸子却落子）。

## 🔒 连接与安全说明

### HTTP API
- **基础地址**: `http://192.168.199.10:60010`

## 必需环境

执行任何操作前，必须确认：
- 机器人已开机且网络可达（`192.168.199.10`）

## 📐 坐标系统

### 棋盘坐标 (x, y)
注意，下面的“左右”和“上下”的定义，都是以使用者的视角来看的，对机器人自己来说则刚好相反。

| 位置 | 坐标 |
|------|------|
| 右上角 | (0, 0) |
| 左下角 | (12, 12) |

### 棋盒坐标 (x, y)

| 棋盒 | 右上角 | 左下角 |
|------|--------|--------|
| 右棋盒 | (-3.8, 0) | (-1.8, 7) |
| 左棋盒 | (14.2, 0) | (15.8, 7) |

## 工作流

### 流程一：取子并落子（最常见场景）

```bash
# 1. 查找棋盒棋子
curl --location 'http://192.168.199.10:60010/skill-detect-box'

# 2. 解析出目标棋子坐标后，移动并取子 (action=1)
curl --location 'http://192.168.199.10:60010/skill-move-tcp?x=-3.1&y=1.5&action=1'

# 3. 只有吸子成功后，才移动到目标位置并落子 (action=2)
curl --location 'http://192.168.199.10:60010/skill-move-tcp?x=6&y=6&action=2'
```

### 流程二：智能取子（CV检测 + 缓存重试）

1. 调用 `skill-detect-box` 获取所有棋子坐标缓存。
2. 遍历缓存中的坐标尝试取子。
3. 如果所有缓存坐标都尝试失败：
    - 语音提示用户"取子失败，请整理棋盒或放入新棋子"。
    - 结束本次取子流程（不循环等待）。

```bash
# 1. 查找棋盒棋子
curl --location 'http://192.168.199.10:60010/skill-detect-box'

# 2. 尝试取第一个
curl --location 'http://192.168.199.10:60010/skill-move-tcp?x=x1&y=y1&action=1'

# 3. 失败则尝试取第二个
curl --location 'http://192.168.199.10:60010/skill-move-tcp?x=x2&y=y2&action=1'

# 4. 全部失败，提示用户并重试
curl --location 'http://192.168.199.10:60010/skill-tts-chinese?content=取子失败，请整理棋盒或放入新棋子'
# ... 结束
```

### 流程三：表情控制

```bash
# 显示特定表情
curl --location 'http://192.168.199.10:60010/skill-show-emotion?code=008'
```

表情编号 code：

| 编号 | 表情 |
|------|------|
| 002 | 快乐 |
| 003 | 哭 |
| 004 | 默认 |
| 008 | 兴趣 |
| 011 | 摇头轻快 |
| 012 | 摇头否认 |
| 013 | 消失 |
| 014 | 出现 |

### 流程四：语音播报

```bash
curl --location 'http://192.168.199.10:60010/skill-tts-chinese?content=你好'
```

### 流程五：播放音乐

```bash
# 异步调用，播放背景音乐 (仅支持 16000Hz 单声道 MP3)
curl --location 'http://192.168.199.10:60010/skill-play-audio' --form 'audio=@"/path/to/music.mp3"'
```

### 流程六：清理棋盘

把棋盘上的子收回棋盒。由于清理过程可能需要几分钟，此接口为异步调用，需要通过轮询该接口并判断返回的 `result` 字段来获取清理进度（`running`、`done` 或 `error`）。

```bash
# 轮询调用，直到 result 变为 done 或 error
curl --location 'http://192.168.199.10:60010/skill-clean-board'
```

### 流程七：查找棋盒棋子

```bash
# 返回包含棋子坐标数组的 JSON 对象，其中 color 1=黑, 2=白
curl --location 'http://192.168.199.10:60010/skill-detect-box'
```

### 流程八：查找棋盘棋子

```bash
# 返回包含棋盘上棋子坐标数组的 JSON 对象，其中 color 1=黑, 2=白
curl --location 'http://192.168.199.10:60010/skill-detect-board'
```

### 流程九：拍照

```bash
# id: 0=前置, 1=右边, 2=左边
curl --location 'http://192.168.199.10:60010/skill-take-photo?id=0'
```

### 流程十：录音

```bash
# 开始录音
curl --location 'http://192.168.199.10:60010/skill-record?code=0'
# 结束录音
curl --location 'http://192.168.199.10:60010/skill-record?code=1'
```

### 流程十一：显示图片

```bash
curl --location 'http://192.168.199.10:60010/skill-show-image' --form 'image=@"/path/to/image.png"'
```

## 控制指令速查表

### HTTP API 指令

| 操作 | 方法 | URL |
|------|------|-----|
| 复位机械臂 | GET | `http://192.168.199.10:60010/skill-move-home` |
| 取落子控制 | GET | `http://192.168.199.10:60010/skill-move-tcp?x=1&y=2&action=1` |
| 语音播报 | GET | `http://192.168.199.10:60010/skill-tts-chinese?content=中文` |
| 播放音乐 | POST | `http://192.168.199.10:60010/skill-play-audio` |
| 看棋盘状态 | GET | `http://192.168.199.10:60010/skill-look-board` |
| 清理棋盘 | GET | `http://192.168.199.10:60010/skill-clean-board` |
| 查找棋盒棋子 | GET | `http://192.168.199.10:60010/skill-detect-box` |
| 查找棋盘棋子 | GET | `http://192.168.199.10:60010/skill-detect-board` |
| 显示表情 | GET | `http://192.168.199.10:60010/skill-show-emotion?code=008` |
| 拍照 | GET | `http://192.168.199.10:60010/skill-take-photo?id=0` |
| 录音 | GET | `http://192.168.199.10:60010/skill-record?code=0` |
| 停止录音 | GET | `http://192.168.199.10:60010/skill-record?code=1` |
| 显示图片 | POST | `http://192.168.199.10:60010/skill-show-image` |

## 错误处理

### 连接异常

| 错误 | 处理方法 |
|------|----------|
| HTTP API 无响应 | 确认机器人服务是否正常运行 |

## 关键注意事项

- 棋盘坐标范围：x ∈ [0, 12]，y ∈ [0, 12]
- 取子失败时自动重试，使用缓存中的下一个位置重试