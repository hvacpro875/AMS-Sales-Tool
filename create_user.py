import os,getpass
import psycopg
from argon2 import PasswordHasher
email=input('Advisor email: ').strip().lower()
password=getpass.getpass('Strong password (at least 14 characters): ')
if len(password)<14:raise SystemExit('Password too short')
with psycopg.connect(os.environ['DATABASE_URL']) as c:
    c.execute('INSERT INTO users(email,password_hash) VALUES(%s,%s) ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash',(email,PasswordHasher().hash(password)))
print('Account created / password updated')
