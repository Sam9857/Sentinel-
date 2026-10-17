
import os
import requests
from dotenv import load_dotenv

load_dotenv(".env", override=True)

TEST_IP = "8.8.8.8"
TIMEOUT = 15


def test_api(name, url, key, headers=None, params=None):
    if not key:
        print(f"{name}: KEY MISSING")
        return

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=TIMEOUT
        )
        print(f"{name}: HTTP {response.status_code}")

        if response.status_code == 200:
            print("  Request successful")
        elif response.status_code == 401:
            print("  Authentication failed: check the key")
        elif response.status_code == 403:
            print("  Access denied: check permissions")
        elif response.status_code == 429:
            print("  Rate limit or quota reached")
        else:
            print("  Check provider response and account settings")

    except requests.RequestException as error:
        print(f"{name}: CONNECTION ERROR - {type(error).__name__}")


vt = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
abuse = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ipinfo = os.getenv("IPINFO_API_KEY", "").strip()
ipqs = os.getenv("IPQS_API_KEY", "").strip()

test_api(
    "VirusTotal",
    f"https://www.virustotal.com/api/v3/ip_addresses/{TEST_IP}",
    vt,
    headers={"x-apikey": vt, "Accept": "application/json"}
)

test_api(
    "AbuseIPDB",
    "https://api.abuseipdb.com/api/v2/check",
    abuse,
    headers={"Key": abuse, "Accept": "application/json"},
    params={"ipAddress": TEST_IP, "maxAgeInDays": "90"}
)

test_api(
    "IPinfo",
    f"https://ipinfo.io/{TEST_IP}",
    ipinfo,
    params={"token": ipinfo}
)

test_api(
    "IPQualityScore",
    f"https://ipqualityscore.com/api/json/ip/{ipqs}/{TEST_IP}",
    ipqs
)
