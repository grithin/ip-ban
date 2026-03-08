import sqlalchemy
import models
engine = sqlalchemy.create_engine("sqlite:///sqlite3.db")


def setup(reset=False, force_remake=False):
	if reset:
		with engine.begin() as conn:
			conn.execute(sqlalchemy.text("drop table if exists ip_log"))
			conn.execute(sqlalchemy.text("drop table if exists cidr_score"))
			conn.execute(sqlalchemy.text("drop table if exists ip_log_file"))
			conn.execute(sqlalchemy.text("drop table if exists ip_whitelist"))
			conn.execute(sqlalchemy.text("drop table if exists cidr_external"))
			conn.execute(sqlalchemy.text("drop table if exists cidr_list_file"))

	#+{ Ensure db exists
	# Create an Inspector object
	insp = sqlalchemy.inspect(engine)
	# Check if the table exists
	if force_remake or not insp.has_table('ip_log'):
		models.Base.metadata.create_all(engine)

	#+}




# special handling for truncate for sqlite3 that doesn't have the command
def truncate(conn: sqlalchemy.Connection, table):
	conn.execute(sqlalchemy.text("DELETE FROM "+table))
	# sqlalchemy somehow doesn't create sqlite_sequence # conn.execute(sqlalchemy.text("UPDATE SQLITE_SEQUENCE SET seq = 0 WHERE name = :t"), {"t":table})


def clear_tables():
	with engine.begin() as conn:
		truncate(conn, "cidr_external")
		truncate(conn, "cidr_list_file")
		truncate(conn, "ip_log")
		truncate(conn, "cidr_score")
		truncate(conn, "ip_log_file")
		truncate(conn, "ip_whitelist")



# Option 2: Explicitly managing connection and commit
# with engine.connect() as conn:
#     conn.execute(text("TRUNCATE TABLE your_table_name"))
#     conn.commit() # Explicit commit needed when not using engine.begin()
