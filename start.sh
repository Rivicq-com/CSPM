#!/bin/bash
export JWT_SECRET="rivicq-unified-jwt-secret-2026"
export AUTH_DB_PATH="data/rivicq_auth.db"
export AUTH_BOOTSTRAP_EMAIL="admin@rivicq.de"
export AUTH_BOOTSTRAP_PASSWORD="m/pUoJZYeDQeFZZWZyqnh9Bp"
export AUTH_BOOTSTRAP_NAME="Workspace Admin"
export AUTH_BOOTSTRAP_ROLE="admin"
export AUTH_ALLOWED_DOMAINS="rivicq.de"
export GITHUB_OAUTH_CLIENT_ID="Ov23liWkEXabdaIK9WN6"
export GITHUB_OAUTH_CLIENT_SECRET="Ov23liR8CMinSxsnOOBs"
export GITHUB_OAUTH_REDIRECT_URL="http://localhost:8080/api/v1/auth/github/callback"
exec /tmp/cryptobom-server
