---
name: playwright-best-practices
description: Python Playwright best practices when writing code for stability, maintainability.Use when creating or modifying python playwright code.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: Jhonatan-de-Souza/playwright-best-practices-skills.md
# corpus-url: https://github.com/Jhonatan-de-Souza/playwright-best-practices-skills.md/blob/89746f4a1cc7399ec97bb3bbee2fd580525d971f/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# Playwright best practices

Create stable and maintanable playwright code using the following best practices. The goal is to create easily maintainable and stable code that is resilient to changes in the DOM structure and minimizes flakiness in tests.


## When to use this skill

- Choosing locators for elements in Playwright code.
- Writing Playwright code that is resilient to changes in the DOM structure.
- Improving the stability and maintainability of Playwright tests.

## Core concepts

### Prefer using get_by_ methods
Whenever possible, use Playwright's `get_by_*` methods (like `get_by_role`, `get_by_label`, `get_by_placeholder`, etc.) as they are more semantic and resilient to changes in the DOM structure.

```python
# Good: Using get_by_role
page.get_by_role("button", name="Submit").click()

# Avoid: Using CSS selectors directly
page.locator("button.submit-btn").click()
```

### Prefer User-Facing Attributes**

Use locators based on user-visible attributes (role, text, label, placeholder) instead of XPath or CSS class selectors. User-facing attributes are more resilient to DOM changes.

```python
# Good: User-facing attributes
page.get_by_role("textbox", name="Username").fill("user123")
page.get_by_label("Email").fill("user@example.com")
page.get_by_placeholder("Enter password").fill("secret")

# Avoid: CSS class selectors
page.locator(".form-input-class").fill("value")
```

### Chain and Filter Locators

Chain locators to narrow down searches to specific parts of the page for better precision.
```python
# Good: Chaining locators
page.locator("nav").get_by_role("link", name="Products").click()
page.get_by_role("article").filter(has_text="Featured").get_by_role("button").click()
```

### Avoid Strictness Issues

Create locators that uniquely identify target elements. Avoid using `.first()`, `.last()`, or `.nth()` methods when possible, as they can lead to unexpected behavior if the page structure changes.

```python
# Avoid: Using .first() when element is not unique
page.locator("button").first.click()

# Good: Use specific attributes to uniquely identify
page.get_by_role("button", name="Delete Account").click()
page.locator("button", has_text="Confirm").click()
```

### Avoid using XPath or Css Selectors Directly
Use xpaths or css selectors only as a last resort when there are no user-facing attributes available to uniquely identify an element. XPaths and CSS selectors are more brittle and prone to breaking with changes in the DOM structure.

good code
```python
# Good: Using get_by_role for Goodreads
page.get_by_role("searchbox", name="Search").fill("Python Programming")
page.get_by_role("button", name="Search").click()
book_link = page.get_by_role("link", name="Python Programming").first
book_link.click()
page.get_by_role("button", name="Want to Read").click()
```
bad code
```python
# Avoid: Using XPath and CSS selectors
page.locator("xpath=//input[@id='searchField']").fill("Python Programming")
page.locator("button.searchBtn").click()
page.locator("xpath=//a[contains(@href, '/book/')]").first.click()
page.locator("div.actionLinkLite > a[data-action='add-to-shelf']").click()
```