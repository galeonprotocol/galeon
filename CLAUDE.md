# Galeon

Private payments using EIP-5564 stealth addresses. Mantle Hackathon 2025.

## Critical Files

- `galeon-hackathon-plan.md` - **DO NOT MODIFY** unless explicitly requested
- `PROGRESS.md` - Global progress tracker (update on major milestones)
- `apps/*/PROGRESS.md` - App-specific progress
- `packages/*/PROGRESS.md` - Package-specific progress

## Repository and Ops

- Repo lives at `github.com/galeonprotocol/galeon` (moved from `mateodaza/galeon`, 21 Nov 2026). Push access: Mateo and Carlos only.
- This repo stays **public**. Security-sensitive work (unfixed vulnerabilities, review findings before fixes) stays private until fixed.
- All non-code work (grant status, deadlines, decisions, contracts, money rules) lives in the private repo `galeonprotocol/galeon-ops` (local: `../galeon-ops`). Read its `CLAUDE.md`, `STATUS.md` and `DEADLINES.md` before planning work, and record decisions there, not here. Never copy private ops content into this public repo.
- Technical work is tracked here (issues, PRs, public project board); ops tasks are tracked in `galeon-ops`.
- Vercel (`galeon-web`) is connected to this repo. Railway is intentionally **not** connected while production is stopped: reconnecting makes every push to `main` redeploy the worker and scheduler.

## Commands

```bash
pnpm dev              # Start all in dev mode
pnpm build            # Build all
pnpm typecheck        # TypeScript check
pnpm test             # Run tests
pnpm --filter web dev # Frontend only
pnpm --filter api dev # Backend only
```

## Code Standards

- **Files**: <300 LOC target, 1000 max
- **Functions**: <50 LOC
- **No `any`**: Use strict TypeScript
- **DRY**: Shared crypto logic in `packages/stealth`

## Naming

| Type      | Style           | Example              |
| --------- | --------------- | -------------------- |
| Files     | kebab-case      | `stealth-service.ts` |
| Types     | PascalCase      | `StealthKeys`        |
| Functions | camelCase       | `derivePortKeys`     |
| Constants | SCREAMING_SNAKE | `SCHEME_ID`          |
| DB tables | snake_case      | `ports`              |

## Security

- NEVER commit secrets
- NEVER store spending keys (derive on-demand)
- Validate all user input at API boundaries

## Stack

Frontend: Next.js 16, React 19, Tailwind v4, wagmi v3
Backend: AdonisJS 6, Lucid ORM, Transmit SSE
Contracts: Solidity 0.8.24, Hardhat 2.28
Crypto: @noble/curves 2.0, @noble/hashes 2.0
