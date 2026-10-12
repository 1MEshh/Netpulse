#!/usr/bin/env bash
set -euo pipefail

echo "[AUDIT] Starting zero-leak and security gate for Netpulse..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

TRACKED_FILES=$(git ls-files 2>/dev/null || true)
if [ -z "$TRACKED_FILES" ]; then
    echo "[AUDIT] No tracked files in git index yet; scanning working tree..."
    TRACKED_FILES=$(find . -maxdepth 4 -not -path '*/.*' -not -path './build*' -not -path './bin*' -type f)
fi

LEAK_FOUND=0

# 1. Scan for absolute filesystem paths (/home/<user>, /Users/<user>, C:\Users\<user>)
echo "[AUDIT] Checking for hardcoded local filesystem paths..."
if grep -rnE '(/home/[a-zA-Z0-9_.-]+|/Users/[a-zA-Z0-9_.-]+|[a-zA-Z]:\\[Uu]sers\\[a-zA-Z0-9_.-]+)' $TRACKED_FILES --exclude="security-audit.sh" 2>/dev/null; then
    echo "[FAIL] Local absolute filesystem path detected in repository files."
    LEAK_FOUND=1
fi

# 2. Scan for current OS user identity if set
CURRENT_USER="${USER:-$(whoami 2>/dev/null || echo "")}"
if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ] && [ "$CURRENT_USER" != "runner" ]; then
    echo "[AUDIT] Checking for OS username leaks ('$CURRENT_USER')..."
    if grep -rniF "$CURRENT_USER" $TRACKED_FILES --exclude="security-audit.sh" 2>/dev/null; then
        echo "[FAIL] OS username leaked in repository files."
        LEAK_FOUND=1
    fi
fi

# 3. Scan for hostname if set
CURRENT_HOST="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo "")"
if [ -n "$CURRENT_HOST" ] && [ "$CURRENT_HOST" != "localhost" ] && [ "$CURRENT_HOST" != "$CURRENT_USER" ]; then
    echo "[AUDIT] Checking for hostname leaks ('$CURRENT_HOST')..."
    if grep -rniF "$CURRENT_HOST" $TRACKED_FILES --exclude="security-audit.sh" 2>/dev/null; then
        echo "[FAIL] Machine hostname leaked in repository files."
        LEAK_FOUND=1
    fi
fi

# 4. Scan for API key or credential prefixes
echo "[AUDIT] Checking for credentials and secret patterns..."
if grep -rnE '(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|vercel_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)' $TRACKED_FILES --exclude="security-audit.sh" 2>/dev/null; then
    echo "[FAIL] Potential secret or API token detected in repository files."
    LEAK_FOUND=1
fi

# 5. Scan for emojis in code, documentation, and comments
echo "[AUDIT] Checking for Unicode emojis..."
python3 -c "
import sys, os, re

# Range for common emoji Unicode planes
emoji_regex = re.compile(
    r'[\U0001F300-\U0001FAFF]'
    r'|[\U00002600-\U000027BF]'
    r'|[\U0001F1E6-\U0001F1FF]'
    r'|[\U00002300-\U000023FF]'
)

tracked = '''$TRACKED_FILES'''.split()
has_emoji = False
for fpath in tracked:
    if not os.path.isfile(fpath):
        continue
    # skip binary files
    try:
        with open(fpath, 'r', encoding='utf-8') as f:
            for line_idx, line in enumerate(f, start=1):
                m = emoji_regex.search(line)
                if m:
                    print(f'[FAIL] Emoji detected in {fpath}:{line_idx} -> {m.group()}')
                    has_emoji = True
    except UnicodeDecodeError:
        continue

if has_emoji:
    sys.exit(1)
" || LEAK_FOUND=1

# 6. Verify git author/committer configuration does not leak personal identity
echo "[AUDIT] Verifying git author configuration..."
GIT_EMAIL=$(git config user.email || echo "")
if [[ "$GIT_EMAIL" != "152591660+1MEshh@users.noreply.github.com" && "$GIT_EMAIL" != *"noreply.github.com"* ]]; then
    echo "[FAIL] Git user.email ('$GIT_EMAIL') is not the required sanitized noreply address."
    LEAK_FOUND=1
fi

GIT_NAME=$(git config user.name || echo "")
if [[ -z "$GIT_NAME" ]]; then
    echo "[FAIL] Git user.name is empty."
    LEAK_FOUND=1
fi

if [ "$LEAK_FOUND" -ne 0 ]; then
    echo "[AUDIT] FAILED: Security, privacy, or policy violation detected."
    exit 1
fi

echo "[AUDIT] PASSED: Zero leaks, zero emojis, sanitized identity verified."
