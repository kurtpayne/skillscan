---
name: flutter-best-practices
description: Flutter performance optimization guidelines. This skill should be used when writing, reviewing, or refactoring Flutter/Dart code to ensure optimal performance patterns. Triggers on tasks involving Flutter widgets, state management, list rendering, image optimization, animations, or app performance improvements.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: kaelen2026/flutter-best-practices
# corpus-url: https://github.com/kaelen2026/flutter-best-practices/blob/a0c2f1bdee3f87fdf2bdd2415a9356052f423384/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# Flutter Best Practices

Comprehensive performance optimization guide for Flutter applications. Contains 40+ rules across 8 categories, prioritized by impact to guide automated refactoring and code generation.

## When to Apply

Reference these guidelines when:
- Writing new Flutter widgets or screens
- Implementing list rendering (ListView, GridView)
- Optimizing widget builds and state management
- Reviewing code for performance issues
- Refactoring existing Flutter/Dart code
- Setting up navigation with GoRouter
- Reducing app size or improving startup time

## Rule Categories by Priority

| Priority | Category | Impact | Prefix |
|----------|----------|--------|--------|
| 1 | Widget Build Optimization | CRITICAL | `build-` |
| 2 | List & Scroll Performance | CRITICAL | `list-` |
| 3 | State Management | HIGH | `state-` |
| 4 | Image & Asset Optimization | HIGH | `image-` |
| 5 | Animation Performance | MEDIUM | `anim-` |
| 6 | Navigation & Routing | MEDIUM | `nav-` |
| 7 | Memory Management | MEDIUM | `memory-` |
| 8 | App Size & Startup | LOW-MEDIUM | `app-` |

## Quick Reference

### 1. Widget Build Optimization (CRITICAL)

- `build-const-widgets` - Use const constructors for static widgets
- `build-split-widgets` - Split large widgets into smaller ones
- `build-avoid-rebuild` - Avoid unnecessary widget rebuilds
- `build-keys` - Use keys correctly for widget identity
- `build-repaint-boundary` - Isolate expensive paint operations
- `build-builder-pattern` - Use Builder pattern for context access

### 2. List & Scroll Performance (CRITICAL)

- `list-builder` - Use ListView.builder for large lists
- `list-item-extent` - Specify itemExtent for fixed-height items
- `list-cache-extent` - Configure cacheExtent appropriately
- `list-sliver` - Use Slivers for complex scrolling layouts
- `list-keep-alive` - Use AutomaticKeepAliveClientMixin wisely
- `list-separated` - Use ListView.separated for dividers

### 3. State Management (HIGH)

- `state-provider` - Use Provider/Riverpod for dependency injection
- `state-selector` - Use Selector/select for granular rebuilds
- `state-notifier` - Prefer ValueNotifier for simple state
- `state-inherited` - Understand InheritedWidget properly
- `state-bloc-events` - Structure BLoC events correctly
- `state-immutable` - Keep state objects immutable

### 4. Image & Asset Optimization (HIGH)

- `image-cached` - Use cached_network_image for remote images
- `image-precache` - Precache images for smooth display
- `image-resize` - Load images at display size
- `image-placeholder` - Use placeholders and error widgets
- `image-format` - Use WebP format for smaller sizes
- `image-memory` - Dispose image resources properly

### 5. Animation Performance (MEDIUM)

- `anim-implicit` - Prefer implicit animations when possible
- `anim-ticker` - Use TickerProviderStateMixin correctly
- `anim-transform` - Use Transform instead of Container
- `anim-opacity` - Use AnimatedOpacity for fade effects
- `anim-hero` - Implement Hero animations properly
- `anim-custom-painter` - Optimize CustomPainter repaints

### 6. Navigation & Routing (MEDIUM)

- `nav-go-router` - Use GoRouter for declarative routing
- `nav-deep-links` - Configure deep linking properly
- `nav-transitions` - Customize page transitions
- `nav-nested` - Handle nested navigation correctly
- `nav-guards` - Implement route guards for auth

### 7. Memory Management (MEDIUM)

- `memory-dispose` - Always dispose controllers and streams
- `memory-listeners` - Remove listeners on dispose
- `memory-isolates` - Use isolates for heavy computation
- `memory-weak-refs` - Use WeakReference for caches

### 8. App Size & Startup (LOW-MEDIUM)

- `app-tree-shake` - Enable icon tree shaking
- `app-deferred` - Use deferred loading for features
- `app-split-debug` - Split debug info for smaller builds
- `app-obfuscate` - Obfuscate Dart code in release
- `app-native-splash` - Configure native splash screen

## How to Use

Read individual rule files for detailed explanations and code examples:

```
rules/build-const-widgets.md
rules/list-builder.md
rules/_sections.md
```

Each rule file contains:
- Brief explanation of why it matters
- Incorrect code example with explanation
- Correct code example with explanation
- Additional context and references

## Full Compiled Document

For the complete guide with all rules expanded: `AGENTS.md`