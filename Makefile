.PHONY: install typecheck test build check-browser check-api check-package

install:
	pnpm install --frozen-lockfile

typecheck:
	pnpm typecheck

test:
	pnpm test

build:
	pnpm build

check-browser:
	pnpm check:browser

check-api:
	pnpm api:check

check-package:
	pnpm package:check
