import json

DOMAINS = None
def mail_check(email, blocklist_path='email_deny_list.json'):
    global DOMAINS

    # Load blocklist on first call (cached for subsequent calls)
    if DOMAINS is None:
        try:
            with open(blocklist_path, 'r') as f:
                data = json.load(f)
                DOMAINS = set(
                    domain.lower() for domain in data.get('denied_domains', [])
                )
        except (FileNotFoundError, json.JSONDecodeError):
            DOMAINS = set()

    if not email or '@' not in email:
        return False

    try:
        parts = email.split('@')
        if len(parts) != 2 or not parts[0] or not parts[1]:
            return False

        domain = parts[1].lower().strip()
        # Return True if NOT in blocklist, False if in blocklist.
        return domain not in DOMAINS
    except (IndexError, AttributeError):
        return False
