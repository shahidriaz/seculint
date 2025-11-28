# 📦 SecuLint Changelog

---
## 🚀 v0.3.0 — Advanced Filtering, Configurable Patterns & AI Pipeline Upgrade (2025-11-28)
### ✨ Added

🆕 --changed-only flag
Scan only modified/staged files in a Git repository (ideal for CI/CD & pre-commit hooks).
🆕 --debug-ignore flag
Shows detailed information about ignored files/folders based on .seculintignore.
🆕 --config flag (JSON configuration)
Supports user-defined pattern rules: enable/disable patterns, override severity, custom regex.
🆕 --json-report flag
Export findings to a consumable JSON file for automation, pipelines, dashboards.
🆕 --include-ext and --exclude-ext filters
Fine-grained control to limit scanning to specific file types.

### 🔧 Improved

#### 🚀 Complete AI pipeline overhaul

- Stable JSON parsing
- Graceful fallback when AI fails
- Never outputs None for AI fields
- Final classification always has consistent values
- AI-rejected findings properly excluded

#### 🧠 Structured AI output
Each finding now includes:

ai_confirmed
ai_severity
ai_reason
ai_type

## 🎯 Smarter ignore handling
More predictable directory & file filtering using .seculintignore.

⚙️ Scanner reliability improvements
Better handling of unreadable files & binary types.

## 🐞 Fixed

- Fixed cases where AI errors resulted in None values
- Corrected missing preview lines in certain encodings
- Ensure correct pattern names and severities propagate into AI analysis
- Resolved extension filter inconsistencies on Windows

---

## 🚀 v0.2.0 — AI-powered Release (2025-11-25)
Added

- 🔥 AI-assisted analysis mode (--enable-ai)
- Uses OpenAI to verify, classify, and explain findings
- Reduces false positives and improves accuracy
- 🌗 Theme toggle (Light/Dark mode) in HTML report
- 🎨 Improved HTML layout and code snippet wrapping

### Improved
- Refactored report layout for readability
- Better severity tagging and badge styling
- Fixed
- Snippet column overflow
- UI spacing issues

---
## 🚀 v0.1.0 — AI-powered Release (2025-11-25)
v0.1.0 — Initial Release
- Basic regex-based secret & privacy leak detection
- JSON and HTML report support
- Command line options, config and severity system
