"""
Import spam comment IPs from a WordPress database into ip-ban.

Usage:
    python3 main.py wp-import /path/to/wp-config.php

Requires: pip install pymysql

Reads DB credentials from wp-config.php, queries wp_comments for spam,
and loads IPs into ip_log. Tracks the last import date per WP source so
re-running only pulls new spam since the previous run.
"""
import re
import ipaddress
from datetime import datetime


def parse_wp_config(config_path):
    """Extract DB credentials and table prefix from wp-config.php."""
    with open(config_path, 'r') as f:
        content = f.read()

    def get_define(key):
        match = re.search(r"define\s*\(\s*['\"]" + key + r"['\"]\s*,\s*['\"]([^'\"]*)['\"]", content)
        if not match:
            raise ValueError(f"Could not find {key} in wp-config.php")
        return match.group(1)

    host = get_define('DB_HOST')
    port = 3306
    if ':' in host and not host.startswith('/'):  # not a socket path
        host, port_str = host.rsplit(':', 1)
        port = int(port_str)

    prefix_match = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]*)['\"]", content)
    prefix = prefix_match.group(1) if prefix_match else 'wp_'

    return {
        'host': host,
        'port': port,
        'user': get_define('DB_USER'),
        'password': get_define('DB_PASSWORD'),
        'database': get_define('DB_NAME'),
        'prefix': prefix,
    }


def import_wp_spam(config_path, bs, models):
    """
    Query WordPress spam comments and load IPs into ip_log.
    Tracks last import per source — re-runs only pull new spam.
    """
    try:
        import pymysql
        import pymysql.cursors
    except ImportError:
        print("pymysql not installed. Run: pip install pymysql")
        return

    config = parse_wp_config(config_path)
    source_key = f"wp:{config['host']}/{config['database']}"
    prefix = config['prefix']

    # Check for a previous import to use as a date cutoff
    existing = bs.query(models.IpLogFiles).filter_by(file=source_key).first()
    last_date = existing.date if existing else None

    if last_date:
        print(f"Last import: {last_date} — fetching newer spam only")
    else:
        print(f"First import from {config['database']} — fetching all spam")

    # Connect to WordPress DB
    try:
        conn = pymysql.connect(
            host=config['host'],
            port=config['port'],
            user=config['user'],
            password=config['password'],
            database=config['database'],
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
    except Exception as e:
        print(f"Could not connect to WordPress DB: {e}")
        return

    try:
        with conn.cursor() as cursor:
            query = f"""
                SELECT DISTINCT
                    comment_author_IP,
                    DATE(comment_date) AS comment_date
                FROM {prefix}comments
                WHERE comment_approved = 'spam'
                  AND comment_author_IP != ''
                  AND comment_author_IP IS NOT NULL
            """
            params = []
            if last_date:
                query += " AND comment_date > %s"
                params.append(last_date)

            cursor.execute(query, params)
            rows = cursor.fetchall()
    finally:
        conn.close()

    if not rows:
        print("No new spam IPs found")
        return

    # Create or update the source record
    now = datetime.now()
    if existing:
        existing.date = now
        bs.flush()
        file_record = existing
    else:
        file_record = models.IpLogFiles(file=source_key, date=now)
        bs.add(file_record)
        bs.flush()

    # Insert IPs into ip_log
    count = 0
    skipped = 0
    batch = []
    for row in rows:
        ip_str = row['comment_author_IP'].strip()
        try:
            ip = ipaddress.IPv4Address(ip_str)
        except (ipaddress.AddressValueError, ValueError):
            skipped += 1  # skip IPv6 and malformed
            continue

        date = row['comment_date']
        if not hasattr(date, 'year'):
            date = datetime.strptime(str(date), "%Y-%m-%d")

        batch.append(models.IpLog(
            ip=int(ip),
            date=date,
            reason='wp_spam',
            file_id=file_record.id
        ))
        if len(batch) >= 100:
            bs.add_all(batch)
            bs.flush()
            count += len(batch)
            batch = []

    if batch:
        bs.add_all(batch)
        count += len(batch)

    bs.commit()

    print(f"Imported {count} spam IPs from {config['database']}", end='')
    if skipped:
        print(f" ({skipped} non-IPv4 skipped)", end='')
    print()
