from datetime import datetime, timezone, timedelta

now = datetime.now(timezone.utc)
expiry_dt = now + timedelta(days=30)
expiry = expiry_dt.strftime('%Y-%m-%d')
print(expiry)