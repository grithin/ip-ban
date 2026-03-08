import os
import sys
import csv
import subprocess
import tempfile
import ipaddress
import tools
import models
from datetime import datetime
from sqlalchemy import func, and_
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import sessionmaker
import db
import wp_import

script_dir = os.path.dirname(os.path.realpath(__file__))
lists_dir = os.path.join(script_dir, 'ip-ban-lists')
whitelist_dir = os.path.join(script_dir, 'ip-ban-whitelist')
cidr_lists_dir = os.path.join(script_dir, 'ip-ban-cidr-lists')



# setup (remake db)
#reset = True
reset = False

db.setup(reset, force_remake=True)

# ensure expected directories exist
for _d in [lists_dir, whitelist_dir, cidr_lists_dir, 'out']:
	os.makedirs(_d, exist_ok=True)

# base session
bs = sessionmaker(bind=db.engine)()




# --- IP log loading ---

def load_ip_logs():
	print('Loading Logs')
	for filename in os.listdir(lists_dir):
		list_csv_path = os.path.join(lists_dir, filename)

		count = bs.query(func.count(models.IpLogFiles.id)).filter(models.IpLogFiles.file==filename).scalar()
		if count > 0:
			print("Skipping log file: " + filename)
			continue

		# Create file record first to get its ID
		log_file = models.IpLogFiles(file=filename, date=datetime.now())
		bs.add(log_file)
		bs.flush()

		delimiter = tools.find_delimiter(list_csv_path)
		batch = []
		with open(list_csv_path, 'r') as file:
			reader = csv.reader(file, delimiter=delimiter)
			next(reader)
			for row in reader:
				ip = ipaddress.ip_address(row[0])
				date = datetime.strptime(row[1], "%Y-%m-%d")
				batch.append(models.IpLog(ip=int(ip), date=date, reason=row[2], file_id=log_file.id))
				if len(batch) >= 100:
					bs.add_all(batch)
					bs.flush()
					batch = []
		if batch:
			bs.add_all(batch)
		bs.commit()
		print(f"Loaded log file: {filename}")




# --- CIDR scoring ---

def get_network_address(ip, net):
	return ipaddress.IPv4Network(str(ip)+'/'+str(net), strict=False).network_address

def create_cidr_blocks(ip):
	for i in range(9):
		net = 32 - i
		start_ip = get_network_address(ip, net)
		start_ip_int = int(start_ip)
		stmt = insert(models.CidrScore).values({"ip_start":start_ip_int, "marks":0, "net":32-i}).on_conflict_do_nothing(index_elements=['ip_start','net'])
		bs.execute(stmt)

def mark_cidr_score(ip):
	for i in range(9):
		net = 32 - i
		start_ip = get_network_address(ip, net)
		bs.query(models.CidrScore).filter_by(ip_start=int(start_ip), net=net).update({"marks": models.CidrScore.marks + 1})

def update_cidr_score(ip):
	create_cidr_blocks(ip)
	mark_cidr_score(ip)

def apply_ip_logs_to_cird_marks():
	print('Updating cidr scores from logs')
	logs = bs.query(models.IpLog).filter(models.IpLog.processed==False)
	for i, log in enumerate(logs):
		ip = ipaddress.IPv4Address(log.ip)
		update_cidr_score(ip)
		log.processed = True
		if i % 500 == 499:
			bs.commit()
	bs.commit()

def find_block16s(ip, net):
	ip = ipaddress.ip_address(ip)
	block_ips = []
	size = pow(2, 32-int(net))
	for i in range(int(size/16)):
		block_ip = int(ip) + (i * 16)
		block_ips.append(block_ip)
	return block_ips

def add_block16_marks():
	print('Adding block16 marks')
	for i in range(4):
		net = 24+i
		cidrs = bs.query(models.CidrScore).filter(models.CidrScore.net==net)
		for cidr in cidrs:
			blocks = find_block16s(cidr.ip_start, cidr.net)
			block_count = bs.query(\
				func.count(models.CidrScore.id)).\
				filter(\
					and_(models.CidrScore.ip_start.in_(blocks),
					models.CidrScore.net==28,
					models.CidrScore.marks>0)).scalar()
			cidr.block16_marks = block_count
	bs.commit()

def make_cidr_bans():
	print('Making cidr bans')
	rules = {
		"24":{"ip":16,"block":6},  # 256 ips, 16 blocks
		"25":{"ip":12,"block":5},  # 128 ips, 8 blocks
		"26":{"ip":10,"block":3},  # 64 ips, 4 blocks
		"27":{"ip":8,"block":2},   # 32 ips, 2 blocks
		"28":{"ip":5},
		"29":{"ip":2},
		"32":{"ip":1}
		}
	for key in rules:
		rule = rules[key]
		if 'block' not in rule:
			rule['block'] = 0
		cidrs = bs.query(models.CidrScore).filter(
			models.CidrScore.net==key,
			models.CidrScore.marks>=rule['ip'],
			models.CidrScore.block16_marks>=rule['block'])
		for cidr in cidrs:
			ip = ipaddress.IPv4Address(cidr.ip_start)
			cidr_string = str(ip)+'/'+str(cidr.net)
			stmt = insert(models.CidrBan).values({"ip_start":cidr.ip_start, "net":cidr.net, "cidr_string":cidr_string, "date":datetime.now()}).on_conflict_do_nothing(index_elements=['ip_start', 'net'])
			bs.execute(stmt)
		bs.commit()




# --- Ban lookup ---

def get_cidr_ban(ip:int, net):
	up_net_count = net-23
	for i in range(up_net_count):
		up_net = 24+i
		start_ip = get_network_address(ipaddress.IPv4Address(ip), up_net)
		ban = bs.query(models.CidrBan).\
				filter(
					models.CidrBan.ip_start==int(start_ip),
					models.CidrBan.net==up_net).first()
		if ban:
			return ban

def get_external_ban(ip_int):
	"""Check if an IP falls within any externally imported CIDR."""
	ip = ipaddress.IPv4Address(ip_int)
	for ext in bs.query(models.CidrExternal).all():
		network = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(ext.ip_start)}/{ext.net}")
		if is_local_network(network):
			continue
		if ip in network:
			return ext
	return None




# --- Ban consolidation ---

def is_local_network(network):
	return (network.is_private or network.is_loopback or
		network.is_reserved or network.is_link_local or
		network.is_multicast)

def is_whitelisted(ip_start_int, net):
	network = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(ip_start_int)}/{net}")
	for entry in bs.query(models.IpWhitelist).all():
		wl = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(entry.ip_start)}/{entry.net}")
		if network.overlaps(wl):
			return True
	return False


def make_consolidated_bans():
	print('Generating consolidated bans')

	# Collect candidates from both internal bans and external imports
	candidates = {}
	for ban in bs.query(models.CidrBan).all():
		candidates[(ban.ip_start, ban.net)] = ban.cidr_string
	for ext in bs.query(models.CidrExternal).all():
		candidates[(ext.ip_start, ext.net)] = ext.cidr_string

	# Load whitelist once
	whitelist = [
		ipaddress.IPv4Network(f"{ipaddress.IPv4Address(e.ip_start)}/{e.net}")
		for e in bs.query(models.IpWhitelist).all()
	]

	# Sort largest ranges first (ascending prefix length) so parents are always
	# processed before their subnets.
	sorted_candidates = sorted(
		[(ip_start, net, cidr_string) for (ip_start, net), cidr_string in candidates.items()],
		key=lambda x: x[1]
	)

	# O(n*32) supernet check using integer math instead of O(n²) supernet_of() loop.
	# accepted_set holds (masked_network_address, prefix_len) for each accepted range.
	# For a candidate at (ip_start, net), its parent at prefix p has address:
	#   ip_start & (0xFFFFFFFF << (32-p))
	accepted_set = set()
	accepted_prefix_lens = set()

	bans = []
	for ip_start, net, cidr_string in sorted_candidates:
		network = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(ip_start)}/{net}")

		if is_local_network(network):
			continue

		if any(network.overlaps(wl) for wl in whitelist):
			print(f'Skipping whitelisted range: {cidr_string}')
			continue

		covered = False
		for p in accepted_prefix_lens:
			if p >= net:
				continue
			mask = (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF
			if (ip_start & mask, p) in accepted_set:
				covered = True
				break

		if not covered:
			accepted_set.add((ip_start, net))
			accepted_prefix_lens.add(net)
			bans.append(cidr_string)

	return bans




IPTABLES_BEGIN = '# BEGIN ip-ban'
IPTABLES_END = '# END ip-ban'

# --- Export ---

def export_bans(bans):
	os.makedirs('out', exist_ok=True)
	with open('out/export.sh', 'w') as f:
		f.write("#!/bin/bash\n")
		f.write("# clear previous ip-ban rules because iptables allows duplicates\n")
		f.write("iptables-save | grep -v ip\\-ban | iptables-restore\n")
		f.write("# write rules\n")
		for ban in bans:
			f.write("iptables -I INPUT -s "+ban+" -m comment --comment \"ip-ban\" -j DROP\n")

def patch_iptables_save(input_file, output_file, bans):
	"""
	Inject ip-ban rules into an iptables-save file.
	If a BEGIN/END ip-ban block already exists, replaces it.
	Otherwise inserts before the COMMIT line in the *filter table.
	The result can be applied with: iptables-restore < output_file
	"""
	with open(input_file, 'r') as f:
		lines = f.readlines()

	ban_block = (
		[IPTABLES_BEGIN + '\n'] +
		[f"-A INPUT -s {ban} -m comment --comment \"ip-ban\" -j DROP\n" for ban in bans] +
		[IPTABLES_END + '\n']
	)

	# Find existing block
	start_idx = None
	end_idx = None
	for i, line in enumerate(lines):
		if line.strip() == IPTABLES_BEGIN:
			start_idx = i
		elif line.strip() == IPTABLES_END and start_idx is not None:
			end_idx = i
			break

	if start_idx is not None and end_idx is not None:
		result = lines[:start_idx] + ban_block + lines[end_idx+1:]
		print(f"Replaced existing ip-ban block ({end_idx - start_idx - 1} old rules → {len(bans)} new rules)")
	else:
		# Insert before COMMIT in *filter table
		result = []
		in_filter = False
		inserted = False
		for line in lines:
			stripped = line.strip()
			if stripped == '*filter':
				in_filter = True
			elif stripped == 'COMMIT' and in_filter and not inserted:
				result.extend(ban_block)
				inserted = True
				in_filter = False
			result.append(line)
		if not inserted:
			print("Warning: no *filter COMMIT found, appending block at end of file")
			result.extend(ban_block)
		print(f"Inserted {len(bans)} rules into {output_file}")

	with open(output_file, 'w') as f:
		f.writelines(result)

def export_cidr_list(outfile=None):
	"""Export consolidated bans as a netset file importable by this tool or compatible with Firehol format."""
	if outfile is None:
		outfile = 'out/cidr-export.netset'
	os.makedirs(os.path.dirname(outfile), exist_ok=True)
	bans = make_consolidated_bans()
	with open(outfile, 'w') as f:
		f.write(f"# ip-ban export {datetime.now().strftime('%Y-%m-%d')}\n")
		for ban in sorted(bans, key=lambda c: ipaddress.IPv4Network(c)):
			f.write(ban + "\n")
	print(f"Exported {len(bans)} CIDRs to {outfile}")




# --- CIDR list import (Firehol / shared exports) ---

def import_cidr_file(filepath):
	"""Import or re-sync a netset file. Re-importing replaces previous entries for that file."""
	filename = os.path.basename(filepath)

	existing = bs.query(models.CidrListFile).filter_by(file=filename).first()
	if existing:
		file_mtime = datetime.fromtimestamp(os.path.getmtime(filepath)).date()
		if file_mtime <= existing.date:
			print(f"Skipping unchanged {filename}")
			return
		# Re-sync: delete old entries then re-import
		bs.query(models.CidrExternal).filter_by(file_id=existing.id).delete()
		existing.date = datetime.now()
		bs.flush()
		file_record = existing
		print(f"Re-syncing {filename}")
	else:
		file_record = models.CidrListFile(file=filename, date=datetime.now())
		bs.add(file_record)
		bs.flush()

	count = 0
	with open(filepath, 'r') as f:
		for line in f:
			line = line.strip()
			if not line or line.startswith('#') or line.startswith(';'):
				continue
			# Strip inline comments ("1.2.3.0/24 ; SBL123" or "1.2.3.0/24 # note")
			cidr_str = line.split(';')[0].split('#')[0].strip()
			if not cidr_str:
				continue
			try:
				network = ipaddress.IPv4Network(cidr_str, strict=False)
			except ValueError:
				print(f"Skipping invalid entry: {cidr_str!r}")
				continue
			stmt = insert(models.CidrExternal).values({
				"ip_start": int(network.network_address),
				"net": network.prefixlen,
				"cidr_string": str(network),
				"file_id": file_record.id
			}).on_conflict_do_nothing(index_elements=['ip_start', 'net', 'file_id'])
			bs.execute(stmt)
			count += 1
			if count % 1000 == 0:
				bs.commit()

	bs.commit()
	print(f"Imported {count} CIDRs from {filename}")

def load_cidr_lists():
	"""Import all files from the ip-ban-cidr-lists/ directory."""
	if not os.path.isdir(cidr_lists_dir):
		print(f"No CIDR lists directory found at {cidr_lists_dir}")
		return
	for filename in os.listdir(cidr_lists_dir):
		import_cidr_file(os.path.join(cidr_lists_dir, filename))




# --- Whitelist management ---

def add_whitelist_entry(cidr_str, note=None):
	try:
		network = ipaddress.IPv4Network(cidr_str, strict=False)
	except ValueError as e:
		print(f"Invalid CIDR: {cidr_str} - {e}")
		return
	ip_start = int(network.network_address)
	net = network.prefixlen
	stmt = insert(models.IpWhitelist).values({
		"ip_start": ip_start,
		"net": net,
		"cidr_string": str(network),
		"note": note,
		"date": datetime.now()
	}).on_conflict_do_nothing(index_elements=['ip_start', 'net'])
	bs.execute(stmt)
	bs.commit()
	print(f"Whitelisted: {network}" + (f"  ({note})" if note else ""))

def load_whitelist():
	if not os.path.isdir(whitelist_dir):
		print(f"No whitelist directory found at {whitelist_dir}")
		return
	for filename in os.listdir(whitelist_dir):
		list_csv_path = os.path.join(whitelist_dir, filename)
		delimiter = tools.find_delimiter(list_csv_path)
		with open(list_csv_path, 'r') as file:
			reader = csv.reader(file, delimiter=delimiter)
			next(reader)
			for row in reader:
				cidr_str = row[0].strip()
				note = row[1].strip() if len(row) > 1 else None
				add_whitelist_entry(cidr_str, note)
		print(f"Loaded whitelist file: {filename}")

def list_whitelist():
	entries = bs.query(models.IpWhitelist).all()
	if not entries:
		print("Whitelist is empty")
		return
	for e in entries:
		print(e.cidr_string + (f"  # {e.note}" if e.note else ""))




# --- CLI ---

cmd = sys.argv[1] if len(sys.argv) > 1 else 'full'
sub = sys.argv[2] if len(sys.argv) > 2 else ''

if cmd == 'full':
	load_ip_logs()
	load_cidr_lists()
	apply_ip_logs_to_cird_marks()
	add_block16_marks()
	make_cidr_bans()
	bans = make_consolidated_bans()
	print(f"Total bans: {len(bans)}")

elif cmd == 'bans':
	print(make_consolidated_bans())

elif cmd == 'export':
	if sub == 'cidr':
		outfile = sys.argv[3] if len(sys.argv) > 3 else 'out/cidr-export.netset'
		export_cidr_list(outfile)
	else:
		export_bans(make_consolidated_bans())
		print("Exported to out/export.sh")

elif cmd == 'patch':
	if not sub:
		print("Usage: python3 main.py patch <iptables-save-file> [output-file]")
		sys.exit(1)
	input_file = sub
	output_file = sys.argv[3] if len(sys.argv) > 3 else input_file
	patch_iptables_save(input_file, output_file, make_consolidated_bans())

elif cmd == 'make':
	outfile = sub if sub else 'out/rules.v4'
	result = subprocess.run(['iptables-save'], capture_output=True, text=True)
	if result.returncode != 0:
		print(f"iptables-save failed: {result.stderr.strip()}")
		sys.exit(1)
	with tempfile.NamedTemporaryFile(mode='w', suffix='.v4', delete=False) as tmp:
		tmp.write(result.stdout)
		tmp_path = tmp.name
	try:
		patch_iptables_save(tmp_path, outfile, make_consolidated_bans())
	finally:
		os.unlink(tmp_path)
	print(f"Apply with: iptables-restore < {outfile}")

elif cmd == 'import':
	if sub == 'cidr':
		if len(sys.argv) < 4:
			print("Usage: python3 main.py import cidr <file>")
			sys.exit(1)
		import_cidr_file(sys.argv[3])
	elif sub == 'cidr-all':
		load_cidr_lists()
	else:
		print(f"Unknown import type: {sub!r}")
		print("Usage: python3 main.py import cidr <file>")
		sys.exit(1)

elif cmd == 'test':
	if len(sys.argv) < 3:
		print("Usage: python3 main.py test <IP>")
		sys.exit(1)
	ip = ipaddress.ip_address(sys.argv[2])
	whitelisted = is_whitelisted(int(ip), 32)
	if whitelisted:
		print('Whitelisted (excluded from bans)')
	else:
		ban = get_cidr_ban(int(ip), 32)
		ext_ban = get_external_ban(int(ip))
		if ban:
			print('Internal ban: ' + repr(ban))
		elif ext_ban:
			print('External ban: ' + ext_ban.cidr_string)
		else:
			print('No ban')

elif cmd == 'whitelist':
	if sub == 'add':
		if len(sys.argv) < 4:
			print("Usage: python3 main.py whitelist add <CIDR> [note]")
			sys.exit(1)
		note = sys.argv[4] if len(sys.argv) > 4 else None
		add_whitelist_entry(sys.argv[3], note)
	elif sub == 'list':
		list_whitelist()
	elif sub == 'load':
		load_whitelist()
	else:
		print(f"Unknown whitelist subcommand: {sub!r}")
		print("Usage: python3 main.py whitelist <add <CIDR> [note] | list | load>")
		sys.exit(1)

elif cmd == 'wp-import':
	if not sub:
		print("Usage: python3 main.py wp-import <wp-config.php path>")
		sys.exit(1)
	wp_import.import_wp_spam(sub, bs, models)

else:
	print(f"Unknown command: {cmd!r}")
	print("Usage: python3 main.py [full|bans|export [cidr [file]]|patch <file> [out]|make [outfile]|import cidr <file>|wp-import <wp-config.php>|test <IP>|whitelist <add|list|load>]")
	sys.exit(1)
