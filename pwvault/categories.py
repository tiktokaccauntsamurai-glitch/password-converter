"""
Category assignment.

Requirement: Gmail credentials must end up in their own printed section,
separate from everything else (including other Google services).

Rules are ordered - the first match wins - so GMAIL is evaluated before the
generic GOOGLE bucket. Everything is data-driven so you can extend
`DOMAIN_RULES` without touching the logic.
"""
from __future__ import annotations

from .model import domain_of

# Printed section order. Anything not listed lands in OTHER, printed last.
CATEGORY_ORDER = [
    "GMAIL",
    "GOOGLE",
    "APPLE",
    "MICROSOFT",
    "EMAIL",
    "FINANCE",
    "SHOPPING",
    "SOCIAL",
    "WORK",
    "DEV",
    "MEDIA",
    "GOV",
    "OTHER",
]

CATEGORY_LABEL = {
    "GMAIL": "GMAIL / GOOGLE MAIL",
    "GOOGLE": "GOOGLE (other services)",
    "APPLE": "APPLE / ICLOUD",
    "MICROSOFT": "MICROSOFT / OUTLOOK",
    "EMAIL": "EMAIL (other providers)",
    "FINANCE": "BANKING & FINANCE",
    "SHOPPING": "SHOPPING & DELIVERY",
    "SOCIAL": "SOCIAL & MESSAGING",
    "WORK": "WORK & PRODUCTIVITY",
    "DEV": "DEVELOPER & HOSTING",
    "MEDIA": "MEDIA & STREAMING",
    "GOV": "GOVERNMENT & UTILITIES",
    "OTHER": "OTHER",
}

# host substring -> category, evaluated in order
DOMAIN_RULES = [
    ("mail.google.com", "GMAIL"),
    ("gmail.com", "GMAIL"),
    ("inbox.google.com", "GMAIL"),
    ("googlemail.com", "GMAIL"),

    ("accounts.google", "GOOGLE"),
    ("youtube.com", "MEDIA"),
    ("google.", "GOOGLE"),
    ("goo.gl", "GOOGLE"),
    ("android.com", "GOOGLE"),

    ("icloud.com", "APPLE"),
    ("apple.com", "APPLE"),
    ("me.com", "APPLE"),

    ("live.com", "MICROSOFT"),
    ("outlook.", "MICROSOFT"),
    ("hotmail.", "MICROSOFT"),
    ("microsoft.com", "MICROSOFT"),
    ("microsoftonline.com", "MICROSOFT"),
    ("office.com", "MICROSOFT"),
    ("azure.com", "MICROSOFT"),
    ("xbox.com", "MICROSOFT"),

    ("yahoo.", "EMAIL"),
    ("proton.me", "EMAIL"),
    ("protonmail.", "EMAIL"),
    ("zoho.", "EMAIL"),
    ("gmx.", "EMAIL"),
    ("mail.ru", "EMAIL"),
    ("yandex.", "EMAIL"),
    ("fastmail.", "EMAIL"),
    ("tutanota.", "EMAIL"),

    ("paypal.", "FINANCE"),
    ("stripe.com", "FINANCE"),
    ("wise.com", "FINANCE"),
    ("revolut.", "FINANCE"),
    ("coinbase.", "FINANCE"),
    ("binance.", "FINANCE"),
    ("kraken.com", "FINANCE"),
    ("chase.com", "FINANCE"),
    ("hsbc.", "FINANCE"),
    ("bank", "FINANCE"),
    ("visa.", "FINANCE"),
    ("mastercard.", "FINANCE"),

    ("amazon.", "SHOPPING"),
    ("ebay.", "SHOPPING"),
    ("aliexpress.", "SHOPPING"),
    ("etsy.com", "SHOPPING"),
    ("wildberries.", "SHOPPING"),
    ("ozon.", "SHOPPING"),
    ("ikea.com", "SHOPPING"),
    ("booking.com", "SHOPPING"),
    ("airbnb.", "SHOPPING"),
    ("uber.com", "SHOPPING"),

    ("facebook.", "SOCIAL"),
    ("instagram.", "SOCIAL"),
    ("x.com", "SOCIAL"),
    ("twitter.", "SOCIAL"),
    ("tiktok.", "SOCIAL"),
    ("telegram.", "SOCIAL"),
    ("web.whatsapp", "SOCIAL"),
    ("whatsapp.", "SOCIAL"),
    ("discord.", "SOCIAL"),
    ("reddit.", "SOCIAL"),
    ("linkedin.", "SOCIAL"),
    ("pinterest.", "SOCIAL"),
    ("snapchat.", "SOCIAL"),
    ("vk.com", "SOCIAL"),
    ("threads.net", "SOCIAL"),

    ("slack.com", "WORK"),
    ("notion.so", "WORK"),
    ("atlassian.", "WORK"),
    ("jira.", "WORK"),
    ("trello.com", "WORK"),
    ("asana.com", "WORK"),
    ("zoom.us", "WORK"),
    ("dropbox.com", "WORK"),
    ("figma.com", "WORK"),
    ("miro.com", "WORK"),

    ("github.", "DEV"),
    ("gitlab.", "DEV"),
    ("bitbucket.", "DEV"),
    ("npmjs.com", "DEV"),
    ("pypi.org", "DEV"),
    ("docker.com", "DEV"),
    ("digitalocean.", "DEV"),
    ("hetzner.", "DEV"),
    ("cloudflare.", "DEV"),
    ("namecheap.", "DEV"),
    ("godaddy.", "DEV"),
    ("vercel.com", "DEV"),
    ("netlify.", "DEV"),
    ("aws.amazon", "DEV"),
    ("openai.com", "DEV"),
    ("anthropic.com", "DEV"),

    ("netflix.", "MEDIA"),
    ("spotify.", "MEDIA"),
    ("twitch.tv", "MEDIA"),
    ("hbomax.", "MEDIA"),
    ("disneyplus.", "MEDIA"),
    ("steampowered.", "MEDIA"),
    ("epicgames.", "MEDIA"),
    ("soundcloud.", "MEDIA"),

    (".gov", "GOV"),
    ("gosuslugi.", "GOV"),
    ("nalog.", "GOV"),
    ("irs.", "GOV"),
]

_EMAIL_TLD_HINTS = ("mail.", "webmail.", "imap.", "smtp.")


def categorise(record) -> str:
    """Return the category id for a Record."""
    host = domain_of(record.url)
    user = (record.username or "").strip().lower()

    # A @gmail.com login is a Gmail credential even when the site is something
    # else? No - the *site* is what you log into. But a login on a Google host
    # with a @gmail.com user is definitely GMAIL.
    if user.endswith("@gmail.com") and ("google" in host or not host):
        return "GMAIL"

    for needle, cat in DOMAIN_RULES:
        if needle in host:
            return cat

    if any(host.startswith(p) for p in _EMAIL_TLD_HINTS):
        return "EMAIL"

    return "OTHER"


def apply_categories(records) -> None:
    for rec in records:
        rec.category = categorise(rec)


def sort_key(category: str) -> int:
    try:
        return CATEGORY_ORDER.index(category)
    except ValueError:
        return len(CATEGORY_ORDER)


def label(category: str) -> str:
    return CATEGORY_LABEL.get(category, category)


def group_by_category(records) -> list:
    """[(category, label, [records...]), ...] in printing order."""
    buckets = {}
    for rec in records:
        buckets.setdefault(rec.category, []).append(rec)
    out = []
    for cat in sorted(buckets, key=sort_key):
        items = sorted(buckets[cat],
                       key=lambda r: (r.display_title.lower(), r.username.lower()))
        out.append((cat, label(cat), items))
    return out
