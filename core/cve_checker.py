import requests

def check_cve(service):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}"
        r = requests.get(url, timeout=6)
        data = r.json()

        cves = []
        for item in data.get("vulnerabilities", [])[:3]:
            cves.append(item["cve"]["id"])

        return cves if cves else ["No CVEs found"]
    except:
        return ["CVE lookup failed"]
