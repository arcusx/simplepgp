link: https://www.gnupg.org/gph/en/manual.html#INTRO

Create key:
gpg --gen-key

List keys:
gpg --list-keys

Export a public key:
gpg --armor --export alice@example.com

Export a private key:
gpg --export-secret-key --armor alice@example.com

Import keys with:
gpg --import keyfile.pem

Decrypt message with:
gpg --output out.txt --decrypt in.txtOr.eml
