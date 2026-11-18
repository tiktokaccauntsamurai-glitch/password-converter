# pwvault

Оффлайн-менеджер паролей для переноса между браузерами и печати на бумагу.
Windows / macOS / Linux, Python 3.9+, **ноль сторонних зависимостей**.

```
import/  →  выбор галочками  →  export/  →  проверка  →  шреддер
                    ↓
        печать A4 / A6 / блокнот 90×170 мм
```

## Запуск

| Система | Как |
|---|---|
| Windows | двойной клик по `run_windows.cmd` |
| macOS | двойной клик по `run_macos.command` (первый раз — правой кнопкой → «Открыть») |
| Любая | `python -m pwvault` |
| Без окна | `python -m pwvault --cli --list` |
| macOS без Python | `pwvault-<версия>-macos-universal.dmg` из [Releases](../../releases) или из артефактов последней сборки в Actions |

Проверить, что всё собрано правильно: `python selftest.py` → `42 passed, 0 failed`.

## Сборка для macOS

`.github/workflows/build-macos.yml` собирает `pwvault.app` (universal2: Apple
Silicon + Intel, Python и Tk внутри) на каждый пуш в `main` и кладёт `.dmg` в
артефакты сборки. Тег `v*` (например `git tag v1.0.0 && git push origin v1.0.0`)
дополнительно публикует `.dmg` в Releases. Рецепт сборки —
`release/pwvault_macos.spec`, на Маке его можно запустить и локально:
`pyinstaller --noconfirm release/pwvault_macos.spec`.

Приложение не подписано сертификатом Apple, поэтому при первом запуске macOS
его заблокирует. Откройте «Системные настройки → Конфиденциальность и
безопасность → Всё равно открыть» или выполните в Терминале
`xattr -dr com.apple.quarantine /Applications/pwvault.app`.

Собранное приложение по умолчанию работает с папками `~/pwvault/import` и
`~/pwvault/export` (не в `~/Documents`, который может синхронизироваться с iCloud).

## Попробовать на демо-данных

```bash
cp samples/chrome/*.csv samples/firefox/*.csv samples/apple/*.csv import/
python -m pwvault
```

В `samples/` лежат синтетические файлы в форматах Chrome, Firefox, Apple
Passwords и Bitwarden. Настоящих паролей там нет.

## Порядок работы

1. **Папки.** Укажите папку импорта (куда вы положили CSV из браузеров) и папку
   экспорта. Они должны быть разными и не вложенными друг в друга — программа
   это проверяет.
2. **Scan.** Файлы читаются, дубликаты между браузерами склеиваются, конфликты
   помечаются жёлтым.
3. **Галочки.** Две независимые колонки: **EXP** — что переносим, **PRN** — что
   печатаем. Кнопки All / None / Invert работают только по видимым строкам,
   то есть вместе с поиском и фильтром категорий.
4. **Вкладка «1. Export».** Выберите форматы → «Export selected → verify against
   disk». Каждый файл после записи перечитывается с диска и сверяется с тем,
   что было отмечено.
5. **Вкладка «2. Print».** Бумага A4 / A6 / блокнот 90 × 170 мм. «Build sheet» →
   «Open in browser» (Ctrl+P) или «Save exact-size PDF» для точного размера.
6. **Вкладка «3. Shred import».** Доступна только после успешной проверки.
   Галочка + слово `SHRED` + подтверждение — исходники перезаписываются и
   удаляются.

## Что важно знать

* Экспорты браузеров — **плейнтекст**. Пока файл лежит на диске, его читает всё,
  что работает от вашего пользователя.
* На SSD перезапись файла не гарантирует уничтожение данных. Реально защищает
  только полнодисковое шифрование (BitLocker / FileVault).
* Программа физически не может выйти в сеть: сетевые модули отключены при
  старте процесса.
* На печати — только английский. Подписи транслитерируются, пароли — никогда:
  не-ASCII символы печатаются как `\uXXXX` с пометкой.

## Документация

* **[PROJECT.md](PROJECT.md)** — как всё устроено: архитектура, форматы CSV,
  правила слияния, верификация, шреддер, модель угроз, типографика печати.
* **[QUESTIONS_AND_IDEAS.md](QUESTIONS_AND_IDEAS.md)** — вопросы к вам и очередь
  идей по развитию.
* **[samples/README.md](samples/README.md)** — что в демо-файлах и откуда брать
  настоящие экспорты.

## Структура

```
pwvault/            пакет: security, model, formats, categories, vault,
                    shred, printing, textutil, audit, gui, cli
samples/            демо-CSV: chrome / firefox / apple / generic
import/             сюда кладёте экспорты браузеров (в git не попадает)
export/             сюда пишутся результаты (в git не попадает)
selftest.py         сквозной тест, 42 проверки
run_windows.cmd     запуск на Windows
run_macos.command   запуск на macOS
release/            рецепт сборки .app (PyInstaller)
.github/workflows/  сборка .dmg для macOS в GitHub Actions
merge_passwords.py  первоначальный скрипт, оставлен как есть
```
