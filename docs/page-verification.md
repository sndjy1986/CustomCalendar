# Page Verification Report

## Pull status
- `git pull --ff-only` could not run because the `work` branch has no configured upstream remote/tracking branch.

## HTTP availability checks
All HTML pages in the repository returned `200 OK` when served locally on `http://127.0.0.1:4173`.

- `/index.html`
- `/login.html`
- `/kid.html`
- `/kid-dashboard.html`
- `/public/kid-login.html`

## Internal link/path checks
All local `href`/`src` references in HTML files resolve to existing files in the repository.

## Page metadata snapshot
- `index.html` → title: `Family Calendar`
- `login.html` → title: `Login`, first `h1`: `Family Calendar Login`
- `kid.html` → title: `Kid Landing | Family Calendar`
- `kid-dashboard.html` → title: `Kid Dashboard | Family Calendar`
- `public/kid-login.html` → title: `Kid Login`, first `h1`: `Kid Login`

## Browser automation note
Attempted browser-level verification with Playwright via the browser tool, but Chromium crashed in this environment (`SIGSEGV`) before navigation. Non-browser checks above completed successfully.
