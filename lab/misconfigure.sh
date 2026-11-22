#!/usr/bin/env bash
# Makes the lab container INSECURE on purpose, so hardaudit has something to find.
# NEVER run this on a real machine.
set -euo pipefail

# --- SSH: weak settings (appended after the default Include line) -----------
cat >> /etc/ssh/sshd_config <<'EOF'

# --- lab: insecure on purpose ---
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 10
X11Forwarding yes
EOF

# --- Accounts -----------------------------------------------------------------
# A second UID 0 account: the classic backdoor left after an intrusion
echo 'toor:x:0:0:backdoor:/root:/bin/bash' >> /etc/passwd
echo 'toor:!:20000:0:99999:7:::' >> /etc/shadow
# An account with an EMPTY password
useradd -m -s /bin/bash guest
passwd -d guest
# A user that becomes root without typing a password
useradd -m -s /bin/bash deploy
echo 'deploy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/deploy
chmod 440 /etc/sudoers.d/deploy

# --- Permissions --------------------------------------------------------------
chmod 644 /etc/shadow                         # password hashes readable by everyone
mkdir -p /etc/app
echo 'db_password=changeme' > /etc/app/config.ini
chmod 666 /etc/app/config.ini                 # anyone can change the app config
chmod u+s /usr/bin/find                       # find + SUID = root shell (GTFOBins)

# --- Logs: synthetic SSH brute force ------------------------------------------
# IPs from RFC 5737 documentation ranges: they do not belong to anyone.
{
  for i in $(seq 1 40); do
    printf 'Nov 22 03:%02d:%02d lab sshd[%d]: Failed password for root from 203.0.113.7 port %d ssh2\n' \
      $((i / 60)) $((i % 60)) $((1000 + i)) $((40000 + i))
  done
  for i in $(seq 1 15); do
    printf 'Nov 22 04:%02d:%02d lab sshd[%d]: Invalid user admin from 198.51.100.23 port %d\n' \
      $((i / 60)) $((i % 60)) $((2000 + i)) $((50000 + i))
  done
  echo 'Nov 22 05:00:00 lab sshd[3000]: Accepted publickey for deploy from 192.0.2.10 port 51000 ssh2'
} > /var/log/auth.log
chmod 640 /var/log/auth.log

# UFW stays installed but disabled (the default), and pam_pwquality keeps
# its default minimum length of 8.
