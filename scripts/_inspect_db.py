import sqlite3
conn = sqlite3.connect("data/nuclei_kb.db")
cursor = conn.cursor()
cursor.execute("SELECT sql FROM sqlite_master WHERE type='table'")
for r in cursor.fetchall():
    print(r[0])
    print()
cursor.execute("SELECT COUNT(*) FROM templates")
print("Total templates:", cursor.fetchone()[0])
cursor.execute("SELECT * FROM templates LIMIT 2")
cols = [d[0] for d in cursor.description]
for r in cursor.fetchall():
    print(dict(zip(cols, r)))
    print()
conn.close()
