# ip-ban

A CIDR-based IP reputation tool. Ingests CSV logs of bad IPs, scores CIDR ranges by spam density, and exports iptables DROP rules. Also supports importing external CIDR lists (Firehol, Spamhaus, shared exports from other users of this tool).

## How it works

When a spammer is assigned an IP block (e.g. `10.0.0.0/27`), multiple IPs within that block appear in spam logs. This tool exploits that pattern:

1. Each logged IP marks its containing CIDR blocks at sizes `/32` through `/24`.
2. Blocks at `/24`–`/27` also count how many `/28` sub-blocks (16-IP ranges) contain spam — this distinguishes commercial bot ranges (consecutive) from zombie IPs (scattered).
3. Ban thresholds are applied per CIDR size (see **Thresholds** below).
4. External CIDR lists (Firehol, Spamhaus, shared exports) are merged in and bypass scoring — they ban unconditionally.
5. Larger bans subsume smaller ones — only the widest applicable ban is exported.
6. Whitelisted CIDRs are excluded from the final output.

### Thresholds

| CIDR | IPs in range | Min spam IPs | Min spam /28 blocks |
|------|-------------|-------------|-------------------|
| /24  | 256         | 16          | 6                 |
| /25  | 128         | 12          | 5                 |
| /26  | 64          | 10          | 3                 |
| /27  | 32          | 8           | 2                 |
| /28  | 16          | 5           | —                 |
| /29  | 8           | 2           | —                 |
| /32  | 1           | 1           | —                 |

## Setup

```sh
pip install sqlalchemy
```

## Input format

Place CSV files in `ip-ban-lists/`. Each file must have a header row. Columns:

```
ip, date, reason
1.2.3.4, 2025-01-15, spam_comment
```

Files already processed are tracked in the database and skipped on re-runs.

## Commands

```sh
# Full pipeline: load logs → score CIDRs → generate bans
python3 main.py

# Print consolidated ban list
python3 main.py bans

# Export bans (-t i4 = iptables, -t nf = nftables, -t ip = ipset, -t ipset = ipset+iptables, -t cidr = netset)
python3 main.py export -t i4              # iptables script to out/export.sh
python3 main.py export -t nf               # nftables script to out/rules.nft
python3 main.py export -t nf /path/to/rules.nft
python3 main.py export -t ip              # ipset restore format to out/ipset.rules
python3 main.py export -t ipset           # ipset + iptables script to out/ipset-iptables.sh

# Inject bans into existing ruleset file (auto-detects iptables vs nftables)
python3 main.py patch /etc/iptables/rules.v4
python3 main.py patch /etc/iptables/rules.v4 out/rules.v4

# Capture live firewall state and inject bans (default: iptables)
python3 main.py make                       # iptables: out/rules.v4
python3 main.py make -t nf                # nftables: out/rules.nft
python3 main.py make -t nf /etc/nftables.conf
python3 main.py make -t ip               # ipset restore: out/ipset.rules
python3 main.py make -t ipset             # ipset + iptables: out/ipset-iptables.sh

# Check whether a specific IP is banned (shows internal ban, external ban, or whitelist status)
python3 main.py test 1.2.3.4
```

### Patching vs shell script export

`export` generates a script that manipulates live firewall at runtime. `patch` edits a ruleset file directly, which is better for persistent rules.

**iptables** — After patching, apply with:

```sh
iptables-restore < /etc/iptables/rules.v4
```

Or patch in place and it will be picked up automatically on next boot/`netfilter-persistent reload`.

**nftables** — After patching, apply with:

```sh
nft -f /etc/nftables.conf
```

The `make` command combines both steps — captures live firewall state and writes a ready-to-restore file:

```sh
# iptables: capture live state, inject bans, write to out/rules.v4
python3 main.py make

# nftables: capture live state, inject bans, write to out/rules.nft
python3 main.py make -t nf

# Apply immediately
python3 main.py make -t nf /etc/nftables.conf && nft -f /etc/nftables.conf
```

All commands use block markers (`# BEGIN ip-ban` / `# END ip-ban` for iptables, same for nftables). On the first run the block is inserted. On subsequent runs it replaces the existing block, so re-running after adding new bans is safe.

### ipset (recommended for large lists)

Using ipset with iptables is more efficient than thousands of individual rules:

```sh
# Export ipset restore format + iptables rule
python3 main.py export -t ipset out/ipset-iptables.sh

# Apply (creates ipset, loads IPs, adds iptables rule)
bash out/ipset-iptables.sh

# Or just update the ipset without touching iptables
python3 main.py export -t ip out/ipset.rules
ipset restore < out/ipset.rules
```

Benefits:
- O(1) lookup instead of O(n) rule traversal
- Single iptables rule references thousands of IPs/CIDRs
- Easier to update (just modify the set, not iptables)

## External CIDR lists (Firehol, Spamhaus, shared exports)

Import pre-vetted CIDR blocklists directly. These bypass internal scoring — any CIDR in an external list is treated as a ban.

```sh
# Import or re-sync a single netset file
python3 main.py import cidr firehol_level1.netset

# Re-sync all files in ip-ban-cidr-lists/ directory
python3 main.py import cidr-all
```

Re-importing a file replaces its previous entries, so you can keep external lists up to date by re-running the import.

### Sources

Download into `ip-ban-cidr-lists/`, then run `python3 main.py import cidr-all`.

**Firehol level1** — high confidence, conservative. Aggregates multiple vetted sources.
```sh
curl -o ip-ban-cidr-lists/firehol_level1.netset \
  https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
```

**Firehol level2** — broader, includes more sources, higher false-positive risk.
```sh
curl -o ip-ban-cidr-lists/firehol_level2.netset \
  https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset
```

**Spamhaus DROP** — IP ranges allocated to professional spam operations. Free for non-commercial use.
```sh
curl -o ip-ban-cidr-lists/spamhaus-drop.txt https://www.spamhaus.org/drop/drop.txt
curl -o ip-ban-cidr-lists/spamhaus-edrop.txt https://www.spamhaus.org/drop/edrop.txt
```

To refresh all sources:
```sh
curl -o ip-ban-cidr-lists/firehol_level1.netset \
  https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
python3 main.py import cidr-all
```

## Sharing / exporting your ban list

Export your consolidated bans as a netset file that others can import with this tool:

```sh
# Export to out/cidr-export.netset
python3 main.py export cidr

# Export to a specific file
python3 main.py export cidr /path/to/my-bans.netset
```

The exported format is compatible with the importer. Note that shared lists are less authoritative than Firehol/Spamhaus — they reflect one server's observed spam, not vetted research.

## WordPress import

Pull spam comment IPs directly from a WordPress database:

```sh
pip install pymysql
python3 main.py wp-import /path/to/wordpress/wp-config.php
```

Reads DB credentials from `wp-config.php`, queries `wp_comments` where `comment_approved = 'spam'` (set by Akismet and manual moderation), and loads IPs into `ip_log`. Tracks the last import date per WordPress source — re-running only pulls spam newer than the previous import.

After importing, run the scoring pipeline to update bans:

```sh
python3 main.py full
```

IPv6 addresses are skipped (iptables IPv4 only).

## Whitelist

Prevent specific IPs or ranges from appearing in the ban output.

```sh
# Add a single entry
python3 main.py whitelist add 1.2.3.0/24 "Cloudflare"

# Load from ip-ban-whitelist/ directory (CSV: cidr, note)
python3 main.py whitelist load

# Show all whitelisted entries
python3 main.py whitelist list
```

Whitelist CSV format (in `ip-ban-whitelist/`):

```
cidr, note
1.1.1.0/24, Cloudflare
8.8.8.0/24, Google DNS
```

## Database

SQLite (`sqlite3.db`) with the following tables:

| Table | Description |
|-------|-------------|
| `ip_log` | Raw bad IP entries from CSV files. `file_id` links to the source file. |
| `ip_log_file` | Tracks which IP log CSV files have been processed |
| `cidr_score` | Per-CIDR mark counts (spam IP count + /28 block count) |
| `cidr_ban` | Ranges that crossed internal ban thresholds |
| `cidr_list_file` | Tracks imported external CIDR list files |
| `cidr_external` | CIDRs imported from external lists, keyed by source file |
| `ip_whitelist` | Ranges excluded from ban output |
