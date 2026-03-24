---
name: weather
version: "1.0"
description: Show weather forecast with cloud cover, wind, and precipitation for planning outdoor activities. Auto-selects best mo...
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: jas-ho/jason-agent-skills
# corpus-url: https://github.com/jas-ho/jason-agent-skills/blob/HEAD/plugins/weather/SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# Weather Forecast

Get hourly weather forecasts to plan outdoor activities (running, cycling, climbing, skiing, etc.).

## When to Invoke

- User asks about weather for outdoor activity planning
- User wants to know when to go outside / best time for a run
- Phrases like "good weather window", "when should I go running", "cloud cover forecast"
- User mentions travel and weather (skill works globally with auto model selection)

## Quick Usage

```bash
~/.claude/skills/weather/weather.sh                    # Vienna (default)
~/.claude/skills/weather/weather.sh -l Innsbruck       # Any location by name
~/.claude/skills/weather/weather.sh -l "Chamonix, FR"  # Include country for accuracy
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-l, --location NAME` | Search location by name | Vienna |
| `--lat N` | Override latitude | 48.18601 |
| `--lon N` | Override longitude | 16.32105 |
| `--days N` | Forecast days (max 2 for ICON-D2) | 2 |
| `--threshold N` | Cloud % for "good" windows | 30 |
| `--model MODEL` | Force model: auto, icon_d2, best_match | auto |
| `--raw` | Output raw JSON | - |

## What It Shows

For each daylight hour:

- **Cloud cover** - Visual bar + percentage
- **Temperature** - Actual temp in Celsius
- **Wind speed** - km/h
- **Rain probability** - Percentage

Plus:

- **Current conditions** - Temp, feels-like, clouds, wind, conditions
- **Best windows** - Consecutive hours with low clouds AND low rain probability
- **Sunrise/sunset** - Daylight planning

## Output Example

```
Weather for Vienna (48.19°N, 16.32°E) - ICON-D2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Now: -1°C (feels -5°C), 82% clouds, 11 km/h wind
Conditions: Overcast
Sunrise: 07:43  Sunset: 16:18

📅 2026-01-08:
  Time  Cloud                         Temp   Wind  Rain%
  08:00   0% ████████████████████  -8°C   7km/h   0% ✓
  09:00   0% ████████████████████  -7°C   8km/h   0% ✓
  10:00   0% ████████████████████  -5°C  10km/h   0% ✓
  11:00   0% ████████████████████  -4°C   9km/h   0% ✓
  12:00  64% ████████░░░░░░░░░░░░  -3°C   9km/h   0%

Best outdoor windows:
  ✓ 08:00-11:00  0% clouds, -8--4°C, 10km/h max wind
```

## Model Selection

The skill auto-selects the best weather model:

| Model | Resolution | Region | Forecast |
|-------|------------|--------|----------|
| ICON-D2 | 2.2km | Central Europe/Alps | 48 hours |
| Best Match | varies | Global | 7+ days |

For Alps/Europe locations, ICON-D2 provides superior accuracy. The skill auto-detects location and switches appropriately.

## Activity Considerations

Different activities have different weather needs:

- **Running/Hiking**: Cloud cover + temperature
- **Cycling**: Wind is critical (>25km/h = challenging)
- **Climbing**: Needs dry conditions, check precipitation history
- **Skiing**: Check specialized sources for snow/avalanche
- **Open water**: Consider water temp (not in this API)

This skill focuses on general outdoor windows. For specialized forecasts:

- Alpine: bergfex.at
- Avalanche: avalanche.report
- Marine: windy.com marine layer

## Data Source

- **API**: Open-Meteo (free, no key required)
- **Units**: Metric (Celsius, km/h, mm)
- **Update frequency**: Every 3 hours (ICON-D2)
- **Timezone**: Auto-detected based on location

## Dependencies

- `curl` - HTTP requests
- `jq` - JSON parsing (`brew install jq`)