#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_passwords.py

Объединяет CSV-экспорты паролей из Chrome, Firefox (и/или Apple Passwords)
в один чистый набор без дубликатов, и создаёт:

  1) apple_import.csv   - готов для импорта в приложение "Пароли" (Mac/iPhone)
                           формат: Title,URL,Username,Password,Notes,OTPAuth
  2) print_ready.html   - открыть в браузере и распечатать (Cmd/Ctrl+P)
  3) review_report.txt  - конфликты и неполные записи, которые лучше
                           проверить руками перед печатью/импортом

ВАЖНО ПО БЕЗОПАСНОСТИ:
  - Запускайте этот скрипт ТОЛЬКО локально на своём компьютере.
  - Не загружайте исходные CSV с паролями ни в какие онлайн-сервисы.
  - После использования удалите исходные CSV-экспорты (они хранят пароли
    в открытом виде) и очистите корзину.

Использование:
    python3 merge_passwords.py chrome.csv firefox.csv -o ./out
"""
import csv
import sys
import argparse
import html
from urllib.parse import urlparse
from collections import defaultdict


def detect_format(fieldnames):
    fields = {f.strip().lower() for f in fieldnames}
    if {'name', 'url', 'username', 'password'}.issubset(fields):
        return 'chrome'
    if {'url', 'username', 'password'}.issubset(fields) and 'httprealm' in fields:
        return 'firefox'
    if {'title', 'url', 'username', 'password'}.issubset(fields):
        return 'apple'
    return 'generic'


def load_file(path):
    entries = []
    with open(path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return entries
        fmt = detect_format(reader.fieldnames)
        for row in reader:
            r = {k.strip().lower(): (v or '').strip() for k, v in row.items()}
            if fmt == 'chrome':
                title, url, user, pwd, notes = r.get('name', ''), r.get('url', ''), r.get('username', ''), r.get('password', ''), r.get('note', '')
            elif fmt == 'firefox':
                url, user, pwd = r.get('url', ''), r.get('username', ''), r.get('password', '')
                title = urlparse(url if '://' in url else 'http://' + url).netloc or url
                notes = ''
            elif fmt == 'apple':
                title, url, user, pwd, notes = r.get('title', ''), r.get('url', ''), r.get('username', ''), r.get('password', ''), r.get('notes', '')
            else:
                title = r.get('title') or r.get('name') or ''
                url = r.get('url') or ''
                user = r.get('username') or r.get('login') or ''
                pwd = r.get('password') or ''
                notes = r.get('notes') or r.get('note') or ''
            entries.append({'title': title, 'url': url, 'username': user,
                             'password': pwd, 'notes': notes, 'source': path})
    return entries


def domain_of(url):
    if not url:
        return ''
    u = url if '://' in url else 'http://' + url
    try:
        netloc = urlparse(u).netloc.lower()
        return netloc[4:] if netloc.startswith('www.') else netloc
    except Exception:
        return url.lower()


def merge(entries):
    groups = defaultdict(list)
    for e in entries:
        key = (domain_of(e['url']), e['username'].lower())
        groups[key].append(e)

    merged, conflicts, empties = [], [], []

    for (domain, user), group in groups.items():
        if not domain and not user:
            empties.extend(group)
            continue
        passwords = {e['password'] for e in group if e['password']}
        if len(passwords) > 1:
            conflicts.append(group)
            best = max(group, key=lambda e: len(e['password']))
        else:
            best = group[0]
        notes = '; '.join(sorted({e['notes'] for e in group if e['notes']}))
        sources = ', '.join(sorted({e['source'] for e in group}))
        title = best['title'] or domain or best['url'] or '(без названия)'
        rec = {'title': title, 'url': best['url'], 'username': best['username'],
               'password': best['password'], 'notes': notes, 'sources': sources}
        if not rec['username'] or not rec['password']:
            empties.append(rec)
        merged.append(rec)

    merged.sort(key=lambda e: e['title'].lower())
    return merged, conflicts, empties


def write_apple_csv(merged, path):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth'])
        for e in merged:
            w.writerow([e['title'], e['url'], e['username'], e['password'], e['notes'], ''])


def write_print_html(merged, path):
    rows = ''.join(f"""
        <tr>
          <td>{html.escape(e['title'])}</td>
          <td>{html.escape(e['url'])}</td>
          <td>{html.escape(e['username'])}</td>
          <td class="pw">{html.escape(e['password'])}</td>
          <td>{html.escape(e['notes'])}</td>
        </tr>""" for e in merged)
    doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Пароли — для печати</title>
<style>
  body {{ font-family: Arial, sans-serif; font-size: 11px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ border: 1px solid #999; padding: 4px 6px; text-align: left; word-break: break-all; }}
  th {{ background: #eee; }}
  .pw {{ font-family: monospace; }}
  @media print {{ @page {{ size: A4; margin: 12mm; }} }}
</style></head>
<body>
<h2>Пароли — {len(merged)} записей</h2>
<table>
<tr><th>Сайт</th><th>URL</th><th>Логин</th><th>Пароль</th><th>Заметки</th></tr>
{rows}
</table>
</body></html>"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(doc)


def write_report(conflicts, empties, path):
    with open(path, 'w', encoding='utf-8') as f:
        f.write("ТРЕБУЕТ ПРОВЕРКИ\n" + "=" * 40 + "\n\n")
        f.write(f"Конфликты (разные пароли для одного сайта+логина): {len(conflicts)}\n")
        for group in conflicts:
            f.write(f"\n  {group[0]['url']} / {group[0]['username']}:\n")
            for e in group:
                f.write(f"    - '{e['password']}' (источник: {e['source']})\n")
        f.write(f"\nЗаписи с пустым логином или паролем: {len(empties)}\n")
        for e in empties:
            f.write(f"  - {e['title']} | {e['url']} | user='{e['username']}' "
                    f"pass={'ЕСТЬ' if e['password'] else 'ПУСТО'}\n")


def main():
    ap = argparse.ArgumentParser(description="Слияние экспортов паролей из Chrome/Firefox/Apple")
    ap.add_argument('files', nargs='+', help='CSV-файлы экспорта паролей')
    ap.add_argument('-o', '--outdir', default='.', help='папка для результатов')
    args = ap.parse_args()

    all_entries = []
    for f in args.files:
        all_entries.extend(load_file(f))

    if not all_entries:
        print("Не удалось прочитать ни одной записи. Проверьте пути к файлам.")
        sys.exit(1)

    merged, conflicts, empties = merge(all_entries)

    write_apple_csv(merged, f'{args.outdir}/apple_import.csv')
    write_print_html(merged, f'{args.outdir}/print_ready.html')
    write_report(conflicts, empties, f'{args.outdir}/review_report.txt')

    print(f"Всего исходных записей: {len(all_entries)}")
    print(f"Уникальных после слияния: {len(merged)}")
    print(f"Конфликтов для проверки: {len(conflicts)}")
    print(f"Неполных записей: {len(empties)}")
    print(f"\nГотово. Файлы в: {args.outdir}/")


if __name__ == '__main__':
    main()
