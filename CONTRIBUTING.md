# Contributing to WAF Console

Thanks for your interest! Here's how to get set up and contribute.

## Development Setup

```bash
git clone https://github.com/desai013/waf-console.git
cd waf-console
npm install
cp .env.example .env        # configure your backend
node server.js              # starts on :3000, :3001, :8080
```

## Running Tests

```bash
npm test                    # run full test suite (117 tests)
```

All tests must pass before submitting a PR.

## Simulating Traffic

```bash
node simulate-traffic.js    # sends attack + legitimate traffic to :8080
```

## Pull Request Guidelines

1. Fork the repo and create a branch from `main`
2. Write tests for any new feature or bug fix
3. Run `npm test` — all 117 tests must pass
4. Open a PR with a clear description of what changed and why

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.**  
Report them privately via [GitHub Security Advisories](https://github.com/desai013/waf-console/security/advisories/new).

## Code Style

- Use `'use strict'` at the top of new modules
- Follow existing naming conventions (camelCase for variables, PascalCase for classes)
- Add JSDoc comments for new public functions
- Keep individual module files focused — one responsibility per file
