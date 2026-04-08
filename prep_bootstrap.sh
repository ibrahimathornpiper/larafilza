#!/private/var/mobile/procursus/bin/sh

# Skip firmware on iOS 18+ as it's not needed and may fail
# /private/var/mobile/procursus/usr/libexec/firmware
/private/var/mobile/procursus/usr/sbin/pwd_mkdb -p /private/var/mobile/procursus/etc/master.passwd >/dev/null 2>&1

# Skip all postinst scripts to avoid failures - they can run later when needed
# /private/var/mobile/procursus/Library/dpkg/info/debianutils.postinst configure 99999
# /private/var/mobile/procursus/Library/dpkg/info/apt.postinst configure 999999
# /private/var/mobile/procursus/Library/dpkg/info/dash.postinst configure 999999
# /private/var/mobile/procursus/Library/dpkg/info/zsh.postinst configure 999999
# /private/var/mobile/procursus/Library/dpkg/info/bash.postinst configure 999999
# /private/var/mobile/procursus/Library/dpkg/info/vi.postinst configure 999999

/private/var/mobile/procursus/usr/sbin/pwd_mkdb -p /private/var/mobile/procursus/etc/master.passwd

# Skip chsh to avoid issues
# /private/var/mobile/procursus/usr/bin/chsh -s /private/var/mobile/procursus/usr/bin/zsh mobile
# /private/var/mobile/procursus/usr/bin/chsh -s /private/var/mobile/procursus/usr/bin/zsh root

# Skip password setup
exit 0
