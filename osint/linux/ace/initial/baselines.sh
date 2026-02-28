# take baselines of network, kernel mods, etc

baselinePath=/root/.dbus/$RANDOM
mkdir -p $baselinePath

ss -plunt > $baselinePath/listening
ss -peunt > $baselinePath/established
lsmod > $baselinePath/kmods
ps auxf > $baselinePath/processes

# TODO encrypt backups
#tar zcf $baselinePath/../.dbus.tar.gz $baselinePath

echo "[+] Baselines added to $baselinePath."
