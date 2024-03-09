@ECHO OFF

echo [GENERATING KEYS]
echo.
"C:\Program Files\Yubico\YubiKey Manager\ykman.exe" piv keys generate --algorithm RSA2048 --pin-policy NEVER --touch-policy ALWAYS 9d pubkey.pem

cls

echo [GENERATING CERTIFICATE]
echo.
"C:\Program Files\Yubico\YubiKey Manager\ykman.exe" piv certificates generate --subject "yubico" 9d pubkey.pem

cls

exit