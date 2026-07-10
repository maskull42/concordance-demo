# Security Policy

## Secrets

API credentials belong only in a repository-local `.env`, which is ignored by Git. The repository must never contain credentials, copied environment files, request authorization headers, or provider exception dumps that can include headers.

The parent application workspace contains an older `.env`; it must not be copied, sourced automatically, or committed here. Live calls are blocked until those credentials are replaced or rotated.

## Static deployment

The production site renders cached JSON and static assets only. It sends no model API request and ships no provider credential to the browser.

## Reporting

Until a private reporting channel is configured, report suspected credential exposure directly to the repository owner rather than opening a public issue.
