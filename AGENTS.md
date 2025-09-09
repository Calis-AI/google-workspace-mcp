# Repository Guidelines

## Project Structure & Module Organization
- Source: `src/` with modules `gmail/`, `calendar/`, `tools/`, `services/`, `oauth/`, `api/`; shared `utils/`, `types/`.
- Entry point: `src/index.ts`.
- MCP server: `src/tools/server.ts` (routes ListTools/CallTool via switch), definitions in `src/tools/definitions.ts`, registry in `src/modules/tools/registry.ts`, handlers `src/tools/*-handlers.ts`.
- Tests: `src/__tests__/**/*.test.ts`; helpers `src/__helpers__/`, mocks `src/__mocks__/`, fixtures `src/__fixtures__/`.
- Build output: `build/`; docs: `docs/` (assets in `docs/assets/`); config/scripts: `config/`, `src/scripts/`, shell utils in `scripts/`. Docker: `Dockerfile`, `Dockerfile.local`.

## Build, Test, and Development Commands
- `npm install`: Install dependencies.
- `npm run type-check`: TypeScript type check (no emit).
- `npm run lint`: ESLint across `src/**/*.ts`.
- `npm run build`: Compile to `build/` and set executable bits.
- `npm start`: Run compiled server (`build/index.js`).
- `npm test` / `npm run test:watch`: Run Jest once / watch mode.
- `npm run watch`: Incremental TypeScript builds.
- `npm run inspector`: Launch MCP Inspector for local tool testing.
- `./scripts/build-local.sh [--verbose] [--tag <name>]`: Build a local Docker image.

## Coding Style & Naming Conventions
- Language: TypeScript (ESM, Node 16+), strict mode.
- Formatting: 2-space indent, LF line endings.
- Naming: files kebab-case (e.g., `service-initializer.ts`); classes PascalCase; functions/vars camelCase.
- Linting: ESLint + `@typescript-eslint`. Fix warnings before PRs.

## Testing Guidelines
- Framework: Jest with `ts-jest` (ESM preset).
- Location/Names: place tests in `src/__tests__/` and end with `.test.ts`.
- Isolation: prefer unit tests; mock Google APIs and network via `src/__mocks__/`.
- Run: `npm test` (use `--coverage` locally if assessing impact).

## Commit & Pull Request Guidelines
- Commits: Conventional Commits (e.g., `feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
- PRs: clear description, link related issues, include tests/docs updates, and note breaking changes.
- Gates: ensure `npm run type-check`, `npm run lint`, and `npm test` pass.

## Security & Configuration Tips
- Never commit secrets. Use env vars: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, optional `LOG_MODE`.
- Local config: `~/.mcp/google-workspace-mcp`. OAuth callback: `http://localhost:8080`.
- Validate scopes/tokens; avoid logging sensitive values. Use `LOG_MODE=strict` for safer local logs.

## Architecture Overview
- Flow: entry (`src/index.ts`) → GSuiteServer (`src/tools/server.ts`) → tool routing (switch) → specific handler → response formatting.

