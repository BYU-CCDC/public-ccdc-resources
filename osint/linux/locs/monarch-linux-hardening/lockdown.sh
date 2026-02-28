### DO NOT ADD THIS TO THE PUBLIC REPO
PAM_PERMIT_PATH=$(find /lib/ -name "pam_permit.so" )
PAM_DIR=$(dirname "$PAM_PERMIT_PATH")
chattr +i $PAM_DIR/*
chattr +i /etc/pam.d/*
