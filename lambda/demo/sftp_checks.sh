#!/bin/bash
# SFTP self-test, run on the SFTP client via SSM (AWS-RunShellScript). Variables arrive
# as shell-quoted assignments decoded from base64 JSON (prepended by the test function).
# Phase "checks":
#   - wrong password and a valid AD user in no SFTP group are both rejected,
#   - RW_USER (read-write) uploads a file with a fresh nonce under SELFTEST_DIR,
#   - RO_USER (read-only) downloads it; its upload and delete are refused,
#   - neither user can reach the canary file outside their folder.
# Phase "cleanup": RW_USER removes the self-test file and directory.
# Passwords are fetched from Secrets Manager at run time and handed to ssh through an
# askpass helper: never on a command line, in a template or in a log.
set -euo pipefail
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT; chmod 700 "$W"

# Pin the server host key to the fingerprint Transfer Family reports for this server
# (Transfer prints it with base64 '=' padding; ssh-keygen without).
ssh-keyscan -T 10 -t rsa "$HOST" 2>/dev/null > "$W/kh"
FP="${FP%%=*}"
if ! ssh-keygen -lf "$W/kh" | awk '{print $2}' | grep -qxF "$FP"; then
  echo "host key fingerprint mismatch (expected $FP)"; ssh-keygen -lf "$W/kh"; exit 1
fi
echo "HOSTKEY_PINNED=$FP"

password_file() {  # password_file USER [wrong] -> path of a 0600 file holding the password
  local user="$1" f="$W/pw.$1.${2:-ok}"
  if [ "${2:-}" = wrong ]; then head -c 18 /dev/urandom | base64 > "$f"
  else
    aws secretsmanager get-secret-value --region "$REGION" --secret-id "$PREFIX/ad-user-$user" \
      --query SecretString --output text | python3 -c 'import json,sys;print(json.load(sys.stdin)["password"])' > "$f"
  fi
  chmod 600 "$f"; echo "$f"
}

# sftp_as USER BATCHFILE [wrong] -> exit status of sftp; batch mode stops at the first failure.
sftp_as() {
  local user="$1" batch="$2" pwf ask
  pwf=$(password_file "$user" "${3:-}")
  ask="$W/askpass.$user.${3:-ok}"; printf '#!/bin/sh\ncat %q\n' "$pwf" > "$ask"; chmod 700 "$ask"
  # -o BatchMode=no must precede -b: -b forces BatchMode=yes and ssh keeps the first value.
  SSH_ASKPASS="$ask" SSH_ASKPASS_REQUIRE=force DISPLAY=none setsid -w \
    sftp -o BatchMode=no -o UserKnownHostsFile="$W/kh" -o StrictHostKeyChecking=yes \
       -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no \
       -o NumberOfPasswordPrompts=1 -o ConnectTimeout=20 \
       -b "$batch" "$user@$HOST" </dev/null 2>&1
}

# expect_refused NAME USER BATCH [wrong]: prints NAME=DENIED when sftp fails, NAME=ALLOWED otherwise.
expect_refused() {
  local name="$1"; shift
  if out=$(sftp_as "$@"); then echo "$out" | tail -3; echo "$name=ALLOWED"
  else echo "$out" | tail -2; echo "$name=DENIED"; fi
}

if [ "$PHASE" = cleanup ]; then
  printf -- '-rm %s/%s\n-rmdir %s\n' "$SELFTEST_DIR" "$FILE" "$SELFTEST_DIR" > "$W/clean.batch"
  sftp_as "$RW_USER" "$W/clean.batch" | tail -3
  echo "CLEANUP=OK"
  exit 0
fi

echo "== authentication"
printf 'pwd\n' > "$W/pwd.batch"
expect_refused WRONG_PASSWORD "$RW_USER" "$W/pwd.batch" wrong
expect_refused NO_GROUP_LOGIN "$NOGROUP_USER" "$W/pwd.batch"

echo "== $RW_USER (read-write): upload"
printf 'payment batch 001\ngenerated %s\nnonce %s\n' "$(date -u +%FT%TZ)" "$NONCE" > "$W/$FILE"
echo "UPLOAD_SHA256=$(sha256sum "$W/$FILE" | cut -d' ' -f1)"
printf -- '-mkdir %s\nput %s %s/%s\nls -l %s\n' "$SELFTEST_DIR" "$W/$FILE" "$SELFTEST_DIR" "$FILE" "$SELFTEST_DIR" > "$W/rw.batch"
sftp_as "$RW_USER" "$W/rw.batch"
echo "RW_UPLOAD=OK"

echo "== $RO_USER (read-only): list + download"
mkdir "$W/ro"
printf 'ls -l %s\nget %s/%s %s\n' "$SELFTEST_DIR" "$SELFTEST_DIR" "$FILE" "$W/ro/$FILE" > "$W/ro.batch"
sftp_as "$RO_USER" "$W/ro.batch"
echo "RO_DOWNLOAD_SHA256=$(sha256sum "$W/ro/$FILE" | cut -d' ' -f1)"

echo "== $RO_USER (read-only): writes must be refused"
echo "auditor write attempt" > "$W/ro-attempt.txt"
printf 'put %s %s/ro-attempt.txt\n' "$W/ro-attempt.txt" "$SELFTEST_DIR" > "$W/ro-put.batch"
expect_refused RO_UPLOAD "$RO_USER" "$W/ro-put.batch"
printf 'rm %s/%s\n' "$SELFTEST_DIR" "$FILE" > "$W/ro-rm.batch"
expect_refused RO_DELETE "$RO_USER" "$W/ro-rm.batch"

echo "== folder confinement (canary outside the folder: /$CANARY)"
for u in "$RW_USER" "$RO_USER"; do
  tag=$(echo "$u" | tr '[:lower:]' '[:upper:]')
  for p in "../$CANARY" "/../$CANARY" "/$CANARY" "../../$CANARY"; do
    printf 'get %s %s\n' "$p" "$W/escape.$u" > "$W/esc.batch"
    expect_refused "ESCAPE_${tag}" "$u" "$W/esc.batch" | tail -1
  done
  [ -e "$W/escape.$u" ] && echo "ESCAPE_${tag}_FILE=PRESENT" || echo "ESCAPE_${tag}_FILE=ABSENT"
done

echo "SFTP_CHECKS=DONE host=$HOST"
