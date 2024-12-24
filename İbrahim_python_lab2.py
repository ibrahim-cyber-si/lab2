import re
import csv
import json
from collections import Counter
from bs4 import BeautifulSoup

# 1. Fayl yolları
log_file = r"D:\AZTU\2024_imtahan_payiz\Python\lab2\access_log.txt"
threat_feed_file = r"D:\AZTU\2024_imtahan_payiz\Python\lab2\thread_feed.html"
url_status_report_file = r"D:\AZTU\2024_imtahan_payiz\Python\lab2\url_status_report.txt"
malware_candidates_file = r"D:\AZTU\2024_imtahan_payiz\Python\lab2\malware_candidates.csv"
alert_file = r"D:\AZTU\2024_imtahan_payiz\Python\lab2\alert.json"
summary_report_file = r"D:\AZTU\2024_imtahan_payiz\Python\lab2\summary_report.json"

# 2. Verilmiş qara siyahı domenləri
blacklisted_domains = ["malicious-site.com", "phishing-example.net", "blacklisteddomain.com"]

# 3. Log faylını oxumaq və Regex ilə məlumat çıxarmaq
pattern = r'\"[A-Z]+\s+(?P<url>https?://[^\s]+)\s+HTTP/\d\.\d\"\s(?P<status>\d{3})'

url_status = []  # Bütün URL-lər və status kodları
status_404_urls = Counter()  # 404 status kodu olan URL-lər və sayları

with open(log_file, "r") as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            url = match.group("url")
            status = match.group("status")
            url_status.append((url, status))
            if status == "404":
                status_404_urls[url] += 1

# 4. Bütün URL-ləri və status kodlarını mətn faylına yazmaq
with open(url_status_report_file, "w") as file:
    for url, status in url_status:
        file.write(f"{url} - {status}\n")

# 5. 404 səhvli URL-ləri CSV faylında saxlamaq
with open(malware_candidates_file, "w", newline="") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["URL", "404 Error Count"])
    for url, count in status_404_urls.items():
        writer.writerow([url, count])

# 6. Təhdid kəşfiyyatından qara siyahı domenləri çıxarmaq (veb scraping)
blacklisted_scraped = set()

with open(threat_feed_file, "r") as html_file:
    soup = BeautifulSoup(html_file, "html.parser")
    for link in soup.find_all("a", href=True):
        domain = re.match(r"https?://([^/]+)", link["href"])
        if domain:
            blacklisted_scraped.add(domain.group(1))

# 7. Qara siyahıya uyğun URL-ləri tapmaq
matching_urls = {}
for url, count in status_404_urls.items():
    for domain in blacklisted_domains + list(blacklisted_scraped):
        if domain in url:
            matching_urls[url] = {"status": 404, "occurrences": count}

# 8. Uyğun məlumatları JSON faylına yazmaq (alert.json)
with open(alert_file, "w") as json_file:
    json.dump(matching_urls, json_file, indent=4)

# 9. Xülasə hesabatı JSON formatında saxlamaq (summary_report.json)
summary = {
    "blacklisted_domains_provided": blacklisted_domains,
    "blacklisted_domains_scraped": list(blacklisted_scraped),
    "total_404_urls": len(status_404_urls),
    "matching_blacklist_urls": len(matching_urls)
}

with open(summary_report_file, "w") as json_file:
    json.dump(summary, json_file, indent=4)

print("Bütün analizlər tamamlandı və fayllara yazıldı.")

if __name__ == "__main__":
    print("Kod başqa faylı import etmədən icra edilib.")
else:
    print("Kod başqa faylı import edərək icra edilib.")
