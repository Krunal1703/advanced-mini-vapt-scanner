import requests

def shodan_lookup(target, api_key):
    try:
        url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
        r = requests.get(url, timeout=6)
        data = r.json()

        return {
            "organization": data.get("org"),
            "country": data.get("country_name"),
            "open_ports": data.get("ports", [])
        }
    except:
        return {"error": "Shodan lookup failed"}
