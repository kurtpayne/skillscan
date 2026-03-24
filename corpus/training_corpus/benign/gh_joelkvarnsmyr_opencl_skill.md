---
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: joelkvarnsmyr/openclaw-canvas-lms
# corpus-url: https://github.com/joelkvarnsmyr/openclaw-canvas-lms/blob/709330b2be8568e260e8512acf85f8e8f94d3bff/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: plain_instructions
---
# Canvas LMS Plugin

## Overview

Native OpenClaw plugin providing 23 tools for Canvas LMS integration. Supports any Canvas instance. Includes TimeEdit cross-referencing for assignments without due dates.

## Tools (23)

| # | Tool | Description |
|---|------|-------------|
| 1 | `canvas_list_courses` | List enrolled courses |
| 2 | `canvas_get_course` | Get single course by ID |
| 3 | `canvas_get_course_syllabus` | Get syllabus HTML |
| 4 | `canvas_get_course_modules` | List modules for a course |
| 5 | `canvas_get_module_items` | Get items in a module |
| 6 | `canvas_list_assignments` | List assignments (filterable by bucket) |
| 7 | `canvas_get_assignment` | Get single assignment |
| 8 | `canvas_list_assignment_groups` | Grade weighting/categories |
| 9 | `canvas_get_page` | Get page by URL slug |
| 10 | `canvas_list_submissions` | Own submissions with grades |
| 11 | `canvas_list_announcements` | Course announcements |
| 12 | `canvas_list_discussions` | Discussion topics |
| 13 | `canvas_get_discussion_view` | Full discussion thread |
| 14 | `canvas_list_calendar_events` | Calendar events |
| 15 | `canvas_list_planner_items` | Planner items (requires dates) |
| 16 | `canvas_timeedit_crossref` | Cross-reference assignments with TimeEdit schedule |
| 17 | `canvas_get_enrollments` | Enrollments with grades |
| 18 | `canvas_get_tabs` | Course navigation tabs |
| 19 | `canvas_list_favorites` | Favorite courses |
| 20 | `canvas_list_files` | List files (may 403 for students) |
| 21 | `canvas_get_file` | Get file by ID |
| 22 | `canvas_list_quizzes` | List quizzes (404 for New Quizzes) |
| 23 | `canvas_get_quiz` | Get quiz by ID (404 for New Quizzes) |

## Usage Examples

```
# List courses
canvas_list_courses

# Upcoming assignments for a course
canvas_list_assignments course_id:4538 bucket:upcoming order_by:due_at

# Assignments with grade status
canvas_list_assignments course_id:4538 bucket:past order_by:due_at include:["submission"]

# Get a specific page
canvas_get_page course_id:4538 page_slug:kurshandbok

# Submissions with grades and comments
canvas_list_submissions course_id:4538 include:["assignment","submission_comments"]

# Announcements across courses
canvas_list_announcements course_ids:[4538,3655]

# Planner items (requires both dates)
canvas_list_planner_items start_date:2026-02-20 end_date:2026-02-27

# Cross-reference with TimeEdit for implicit deadlines
canvas_timeedit_crossref course_id:4538 days_ahead:30
```

## TimeEdit Cross-Reference

Many Canvas assignments lack explicit due dates. The `canvas_timeedit_crossref` tool:

1. Fetches the TimeEdit ICS schedule
2. Fetches all Canvas assignments for the course
3. Keyword-matches assignment names to scheduled events
4. Assigns implicit deadlines based on the last matching event

**When asked about deadlines, schedule, or upcoming work, ALWAYS use this tool** to get the complete picture including undated assignments.

## Finding Files

`canvas_list_files` often returns 403 for student accounts. Instead:

1. Use `canvas_get_course_modules` + `canvas_get_module_items` to find file IDs in module items of type "File"
2. Check page HTML from `canvas_get_page` for file links
3. Use `canvas_get_file` with the found file ID

## Known Limitations

- `canvas_list_files` -> 403 for student permissions. Use `canvas_get_file` with known IDs.
- `canvas_list_quizzes` / `canvas_get_quiz` -> 404 if institution uses New Quizzes (quiz_lti).
- `canvas_list_planner_items` requires both `start_date` and `end_date` in ISO format.
- `canvas_timeedit_crossref` only available when `timeeditUrl` is configured.

## Agent Strategy

1. **Deadlines/schedule** -> `canvas_timeedit_crossref` first, then `canvas_list_planner_items`
2. **Course content** -> `canvas_get_page` with slug, or modules + module items
3. **Grades/submissions** -> `canvas_list_submissions` with include:["assignment","submission_comments"]
4. **News** -> `canvas_list_announcements` + `canvas_list_planner_items`
5. **Files** -> Find IDs via module items/pages, then `canvas_get_file`