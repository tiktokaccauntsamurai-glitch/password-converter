# Sample CSV files

Synthetic test data, generated locally. **No real credentials.** Every password
here is fake and every domain is either a public site with a `demo.*` login or
an `example.*` / `.test` / `.local` reserved name.

These files exist so you can exercise the whole pipeline (scan → merge →
select → export → verify → shred) without ever touching your real vault.

## What is in each file

| File | Dialect | Header |
|---|---|---|
| `chrome/chrome_passwords_sample.csv` | Chrome / Google Password Manager | `name,url,username,password,note` |
| `firefox/firefox_logins_sample.csv` | Firefox `about:logins` export | `"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"` |
| `apple/apple_passwords_sample.csv` | Apple Passwords (macOS/iOS) | `Title,URL,Username,Password,Notes,OTPAuth` |
| `generic/bitwarden_style_sample.csv` | Bitwarden-style generic export | `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp` |

## Edge cases they deliberately cover

* **Cross-browser duplicates** — `accounts.google.com / demo.user@gmail.com`
  appears in Chrome, Firefox and (as Gmail) Apple. They must merge into one row.
* **A genuine conflict** — PayPal has password `Pw8%dFg3Hjk!5Qz` in Chrome and
  `OLD-Pw8%dFg3Hjk` in Firefox. The merge flags it instead of picking silently.
* **Non-ASCII password** — `Пароль#2026!ok` in the Chrome sample. It must never
  be transliterated; on paper it is printed as `Па...` escapes with a
  `*` marker and a legend line.
* **Missing username** — `orphan.example.net` row, flagged as incomplete.
* **HTTP realm entry** — the Firefox `intranet.example.com` row has an
  `httpRealm` and no `formActionOrigin`.
* **TOTP secrets** — three Apple rows carry `otpauth://` URIs, so you can see
  which export formats silently drop them (Chrome and Firefox do).
* **Weak legacy password** — `forum123`, useful for testing a future strength
  audit.
* **Plain-HTTP and LAN hosts** — router, NAS, printer.

## How to use them

```
# copy the ones you want into the import folder, then run the app
cp samples/chrome/*.csv samples/firefox/*.csv samples/apple/*.csv import/
python -m pwvault
```

Or run the built-in end-to-end self test, which uses these files and cleans up
after itself:

```
python selftest.py
```

## Where the real ones come from

| Source | How to export |
|---|---|
| Chrome / Google | `chrome://password-manager/settings` → *Download file* (or passwords.google.com → Settings → Export) |
| Firefox | `about:logins` → `···` menu → *Export Logins…* |
| Apple Passwords (macOS) | Passwords app → **File ▸ Export All Passwords to File** |
| Safari (older macOS) | Safari ▸ Settings ▸ Passwords → `···` → *Export All Passwords* |
| Edge | `edge://wallet/passwords/settings` → *Export passwords* |

Every one of those files is **plaintext**. Move it into the import folder,
process it, and let pwvault shred it — do not let it sit in `Downloads`.
