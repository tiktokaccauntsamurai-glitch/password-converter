# Папка импорта

Кладите сюда CSV-экспорты паролей из браузеров. Программа читает `.csv`,
`.txt` и `.tsv`; этот файл (`.md`) она игнорирует.

| Откуда | Как выгрузить |
|---|---|
| Chrome / Google | `chrome://password-manager/settings` → Download file |
| Firefox | `about:logins` → `···` → Export Logins… |
| Apple Passwords (macOS) | Passwords → File ▸ Export All Passwords to File |
| Edge | `edge://wallet/passwords/settings` → Export passwords |

Все эти файлы — **плейнтекст**. Не оставляйте их в «Загрузках»: перенесите
сюда, обработайте и дайте программе их уничтожить (вкладка «3. Shred import»).

Попробовать без своих паролей:

```
cp ../samples/chrome/*.csv ../samples/firefox/*.csv ../samples/apple/*.csv .
```
