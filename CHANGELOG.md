# Changelog

## Unreleased

- Added layered configuration with the following precedence: embedded JSON, optional `--config` JSON, `OAUTH2_MOCK_*` environment variables, and CLI overrides.
- Added `--host` and `--port` configuration overrides.
- External JSON files can now be partial; nested objects are merged and arrays are replaced as a whole.
- Unknown configuration fields are rejected to prevent silent configuration mistakes.
- The default access restriction code is now empty, so enabling access restriction requires an explicit code.

## 1.2.0

**Braking changes**
New configuration sections "access_restriction". You can just copy&past it from the [default 
configuration](config/application.json).

New Features
- [X] Simple restriction access to oauth2mock
- [X] Processing signals from OS (fast docker restart)

Full changelog:
https://github.com/leonidv/oauth2-mock/milestone/1?closed=1

## 1.1.0
Bugfixes
