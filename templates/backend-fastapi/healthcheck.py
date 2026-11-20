"""컨테이너 HEALTHCHECK 용. 허용된 Host 로 /api/health 를 호출한다.

앱이 TrustedHost 검사를 하므로 Host 를 127.0.0.1 로 보내면 400 을 받는다.
ALLOWED_HOSTS 의 첫 번째 값을 Host 헤더로 쓴다.
"""
import os
import sys
import urllib.request

port = os.environ.get("API_PORT", "8000")
host = os.environ.get("ALLOWED_HOSTS", "localhost").split(",")[0].strip() or "localhost"
request = urllib.request.Request(f"http://127.0.0.1:{port}/api/health", headers={"Host": host})
try:
    with urllib.request.urlopen(request, timeout=2) as response:
        sys.exit(0 if response.status == 200 else 1)
except Exception:
    sys.exit(1)
