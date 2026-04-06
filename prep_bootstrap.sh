#!/private/var/mobile/procursus/bin/sh

/private/var/mobile/procursus/usr/libexec/firmware
/private/var/mobile/procursus/usr/sbin/pwd_mkdb -p /private/var/mobile/procursus/etc/master.passwd >/dev/null 2>&1
/private/var/mobile/procursus/Library/dpkg/info/debianutils.postinst configure 99999
/private/var/mobile/procursus/Library/dpkg/info/apt.postinst configure 999999
/private/var/mobile/procursus/Library/dpkg/info/dash.postinst configure 999999
/private/var/mobile/procursus/Library/dpkg/info/zsh.postinst configure 999999
/private/var/mobile/procursus/Library/dpkg/info/bash.postinst configure 999999
/private/var/mobile/procursus/Library/dpkg/info/vi.postinst configure 999999

/private/var/mobile/procursus/usr/sbin/pwd_mkdb -p /private/var/mobile/procursus/etc/master.passwd

/private/var/mobile/procursus/usr/bin/chsh -s /private/var/mobile/procursus/usr/bin/zsh mobile
/private/var/mobile/procursus/usr/bin/chsh -s /private/var/mobile/procursus/usr/bin/zsh root

if [ -z "$NO_PASSWORD_PROMPT" ]; then
    PASSWORDS=""
    PASSWORD1=""
    PASSWORD2=""
    while [ -z "$PASSWORD1" ] || [ ! "$PASSWORD1" = "$PASSWORD2" ]; do
            PASSWORDS="$(/private/var/mobile/procursus/usr/bin/uialert -b "In order to use command line tools like \"sudo\" after jailbreaking, you will need to set a terminal passcode. (This cannot be empty)" --secure "Password" --secure "Repeat Password" -p "Set" "Set Password")"
            PASSWORD1="$(printf "%s\n" "$PASSWORDS" | /private/var/mobile/procursus/usr/bin/sed -n '1 p')"
            PASSWORD2="$(printf "%s\n" "$PASSWORDS" | /private/var/mobile/procursus/usr/bin/sed -n '2 p')"
    done
    printf "%s\n" "$PASSWORD1" | /private/var/mobile/procursus/usr/sbin/pw usermod 501 -h 0
fi

# === SSH Setup ===
SSH_ETC=/private/var/mobile/procursus/etc/ssh
SSH_RUN=/private/var/mobile/procursus/var/run

# Create required directories
/bin/mkdir -p "$SSH_ETC" "$SSH_RUN"

# Write a permissive sshd_config
cat > "$SSH_ETC/sshd_config" << 'EOF'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM no
PrintMotd yes
Subsystem sftp /private/var/mobile/procursus/usr/libexec/sftp-server
EOF

# Generate host keys (skip if already exist)
KEYGEN=/private/var/mobile/procursus/usr/bin/ssh-keygen
for TYPE in rsa ecdsa ed25519; do
    KEY="$SSH_ETC/ssh_host_${TYPE}_key"
    if [ ! -f "$KEY" ]; then
        "$KEYGEN" -t "$TYPE" -f "$KEY" -N "" > /dev/null 2>&1
    fi
done

# Start sshd in the background
SSHD=/private/var/mobile/procursus/usr/sbin/sshd
if [ -x "$SSHD" ]; then
    "$SSHD" -f "$SSH_ETC/sshd_config" &
fi

rm -f /private/var/mobile/procursus/prep_bootstrap.sh
