#!/usr/bin/env python3
# --- start of script ---
import os, sys, json, shutil, subprocess, requests
from datetime import datetime
ENV_VT="VT_API_KEY"; ENV_ST="ST_API_KEY"; ENV_SHODAN="SHODAN_API_KEY"
ENV_CENSYS_UID="CENSYS_UID"; ENV_CENSYS_SECRET="CENSYS_SECRET"
ENV_ABUSEIPDB="ABUSEIPDB_KEY"; ENV_IPINFO="IPINFO_TOKEN"
TIMEOUT=15
def run_cmd(cmd):
    try:
        out=subprocess.check_output(cmd,stderr=subprocess.DEVNULL,shell=True,timeout=20)
        return out.decode(errors="ignore").strip()
    except subprocess.CalledProcessError:
        return None
    except Exception as e:
        return f"(error running cmd: {e})"
def nice_title(s): print("\n"+("="*len(s))+"\n"+s+"\n"+("="*len(s)))
def whois_ripe(ip): 
    return run_cmd(f"whois -h whois.ripe.net {ip}") if shutil.which("whois") else "(whois not installed)"
def reverse_dns(ip):
    if shutil.which("dig"):
        dig=run_cmd(f"dig -x {ip} +short")
        if dig: return dig
    if shutil.which("host"): return run_cmd(f"host {ip}")
    return "(dig/host not available)"
def ipinfo_lookup(ip,token=None):
    url=f"https://ipinfo.io/{ip}/json"; headers={}
    if token: headers["Authorization"]=f"Bearer {token}"
    try:
        import requests
        r=requests.get(url,headers=headers,timeout=TIMEOUT)
        return r.json() if r.status_code==200 else {"error":f"HTTP {r.status_code}"}
    except Exception as e: return {"error":str(e)}
def team_cymru_asn(ip):
    return run_cmd(f'whois -h whois.cymru.com " -v {ip}"') if shutil.which("whois") else "(whois client not available)"
def circl_pdns(ip):
    try:
        import requests
        r=requests.get(f"https://www.circl.lu/pdns/query/ip/{ip}",timeout=TIMEOUT)
        return r.json() if r.status_code==200 else {"error":f"HTTP {r.status_code}"}
    except Exception as e: return {"error":str(e)}
def vt_ip_report(ip,key):
    if not key: return {"skipped":"no vt key"}
    try:
        import requests
        r=requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                       headers={"x-apikey":key},timeout=TIMEOUT)
        return r.json() if r.status_code==200 else {"error":f"HTTP {r.status_code}"}
    except Exception as e: return {"error":str(e)}
def securitytrails_ip(ip,key):
    if not key: return {"skipped":"no securitytrails key"}
    try:
        import requests
        r=requests.get(f"https://api.securitytrails.com/v1/ips/{ip}",
                       headers={"APIKEY":key},timeout=TIMEOUT)
        return r.json() if r.status_code==200 else {"error":f"HTTP {r.status_code}"}
    except Exception as e: return {"error":str(e)}
def shodan_host(ip,key):
    if not key: return {"skipped":"no shodan key"}
    try:
        import requests
        r=requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={key}",timeout=TIMEOUT)
        return r.json() if r.status_code==200 else {"error":f"HTTP {r.status_code}"}
    except Exception as e: return {"error":str(e)}
def censys_host(ip,uid,secret):
    if not uid or not secret: return {"skipped":"no censys creds"}
    try:
        import requests
        r=requests.get(f"https://search.censys.io/api/v2/hosts/{ip}",
                       auth=(uid,secret),timeout=TIMEOUT)
        return r.json() if r.status_code==200 else {"error":f"HTTP {r.status_code}"}
    except Exception as e: return {"error":str(e)}
def abuseipdb_check(ip,key):
    if not key: return {"skipped":"no abuseipdb key"}
    try:
        import requests
        r=requests.get("https://api.abuseipdb.com/api/v2/check",
                       params={"ipAddress":ip,"maxAgeInDays":90},
                       headers={"Key":key,"Accept":"application/json"},
                       timeout=TIMEOUT)
        return r.json() if r.status_code==200 else {"error":f"HTTP {r.status_code}"}
    except Exception as e: return {"error":str(e)}
def tshark_tls_summary(pcap_path,ip):
    if not shutil.which("tshark"): return "(tshark not installed)"
    out1=run_cmd(f'tshark -r "{pcap_path}" -Y "tls.handshake.type==1 and ip.addr=={ip}" -T fields -e frame.number -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja3')
    out2=run_cmd(f'tshark -r "{pcap_path}" -Y "tls.handshake.type==11 and ip.addr=={ip}" -T fields -e frame.number -e ip.src -e ip.dst -e x509sat.printableString -e tls.handshake.ja3s')
    return {"clienthellos": out1 or "(none)", "servercerts": out2 or "(none)"}
def short_print(obj,indent=2):
    print(json.dumps(obj,indent=indent,sort_keys=True,default=str))
def main():
    ip=input("Enter IP to enrich: ").strip()
    if not ip: 
        print("No IP entered."); return
    vt=os.environ.get(ENV_VT,""); st=os.environ.get(ENV_ST,""); sh=os.environ.get(ENV_SHODAN,"")
    cu=os.environ.get(ENV_CENSYS_UID,""); cs=os.environ.get(ENV_CENSYS_SECRET,"")
    abuse=os.environ.get(ENV_ABUSEIPDB,""); ipinfo_tok=os.environ.get(ENV_IPINFO,"")
    nice_title(f"Enrichment report for {ip} - {datetime.utcnow().isoformat()}Z")
    nice_title("RIPE whois"); print((whois_ripe(ip) or "")[:4000])
    nice_title("Reverse DNS / PTR"); print(reverse_dns(ip))
    nice_title("ipinfo.io (basic)"); short_print(ipinfo_lookup(ip,token=ipinfo_tok))
    nice_title("Team Cymru ASN summary"); print(team_cymru_asn(ip))
    nice_title("CIRCL passive DNS (public)")
    circl=circl_pdns(ip)
    try:
        if isinstance(circl,list):
            print(f"PDNS records found: {len(circl)}"); print(json.dumps(circl[:5],indent=2))
        else: print(circl)
    except Exception: print(circl)
    nice_title("VirusTotal (optional)"); vtj=vt_ip_report(ip,vt); print("Skipped VT (no key)" if "skipped" in vtj else json.dumps(vtj)[:2000])
    nice_title("SecurityTrails (optional)"); stj=securitytrails_ip(ip,st); print("Skipped ST (no key)" if "skipped" in stj else json.dumps(stj)[:2000])
    nice_title("Shodan (optional)"); shj=shodan_host(ip,sh); print("Skipped Shodan (no key)" if "skipped" in shj else json.dumps(shj)[:2000])
    nice_title("Censys (optional)"); cej=censys_host(ip,cu,cs); print("Skipped Censys (no creds)" if "skipped" in cej else json.dumps(cej)[:2000])
    nice_title("AbuseIPDB (optional)"); abj=abuseipdb_check(ip,abuse); print("Skipped AbuseIPDB (no key)" if "skipped" in abj else json.dumps(abj)[:2000])
    pcap=input("\nOptionally enter a pcap path to parse TLS metadata (or press Enter to skip): ").strip()
    if pcap: 
        nice_title("tshark TLS summary"); short_print(tshark_tls_summary(pcap,ip))
    nice_title("Quick heuristic verdict")
    verdict=[]
    if isinstance(circl,list) and len(circl)>5: verdict.append("Passive DNS shows multiple domains → suspicious.")
    if isinstance(ipinfo_lookup(ip),dict):
        pass
    print("\n".join(verdict) if verdict else "No high-confidence flags from quick checks.")
    print("\nDone. Tip: export API keys as env vars to enable optional lookups.")
if __name__=="__main__": main()
