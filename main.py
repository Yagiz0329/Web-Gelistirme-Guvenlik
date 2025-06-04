import argparse
import requests
import logging
import os
from datetime import datetime
from bs4 import BeautifulSoup # HTML ayrıştırma için
import json # JSON çıktı için

# --- LOGLAMA YAPILANDIRMASI ---
# Bilgilendirici ve hata mesajlarını konsola yazmak için.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- ARGÜMANLARIN PARSE EDİLMESİ ---
def parse_arguments():
    """Komut satırı argümanlarını ayrıştırır."""
    parser = argparse.ArgumentParser(description="Web Uygulama Güvenliği Tarayıcısı")
    parser.add_argument('--target', required=True, help='Tarama yapılacak hedef web uygulamasının URL\'si (örn: https://example.com)')
    parser.add_argument('--scan-type', default='quick', choices=['quick', 'full', 'api'], help='Gerçekleştirilecek tarama tipi (quick, full, api)')
    parser.add_argument('--output-format', default='txt', choices=['json', 'html', 'txt'], help='Tarama sonuçlarının çıktı formatı')
    parser.add_argument('--report-path', default='./reports/', help='Sonuç raporunun kaydedileceği dizin')
    parser.add_argument('--verbose', action='store_true', help='Daha detaylı konsol çıktısı sağlar')
    return parser.parse_args()

# --- GÜVENLİK KONTROL FONKSİYONLARI ---

def check_http_headers(target_url, results):
    """
    Hedef URL'nin HTTP güvenlik başlıklarını kontrol eder.
    OWASP Secure Headers Project'ten ilham alınmıştır.
    """
    logging.info(f"HTTP Güvenlik Başlıkları kontrol ediliyor: {target_url}")
    try:
        response = requests.get(target_url, timeout=10) # 10 saniye zaman aşımı
        headers = response.headers
        
        # Kontrol edilecek ana güvenlik başlıkları ve açıklamaları
        security_headers = {
            "Strict-Transport-Security": {
                "description": "HSTS, tarayıcıları siteye sadece HTTPS üzerinden bağlanmaya zorlar, MITM saldırılarını engeller.",
                "severity": "High",
                "recommendation": "Web sunucusu yapılandırmanıza 'Strict-Transport-Security: max-age=31536000; includeSubDomains' başlığını ekleyin."
            },
            "X-Content-Type-Options": {
                "description": "Tarayıcıların MIME türü koklamasını (sniffing) engeller, XSS saldırılarına karşı korur.",
                "severity": "Medium",
                "recommendation": "Web sunucusu yapılandırmanıza 'X-Content-Type-Options: nosniff' başlığını ekleyin."
            },
            "X-Frame-Options": {
                "description": "Sitenizin clickjacking saldırılarına karşı iframe'lerde görüntülenmesini engeller.",
                "severity": "Medium",
                "recommendation": "Web sunucusu yapılandırmanıza 'X-Frame-Options: DENY' veya 'SAMEORIGIN' başlığını ekleyin."
            },
            "Content-Security-Policy": {
                "description": "XSS ve veri enjeksiyonu saldırılarını azaltmaya yardımcı olan bir güvenlik politikası tanımlar.",
                "severity": "High",
                "recommendation": "Web sunucusu yapılandırmanıza uygun bir 'Content-Security-Policy' başlığı ekleyin (örn: 'default-src 'self'; script-src 'self'')."
            },
            "Referrer-Policy": {
                "description": "Referrer bilgisinin ne kadarının gönderileceğini kontrol eder, bilgi sızıntılarını önler.",
                "severity": "Low",
                "recommendation": "Web sunucusu yapılandırmanıza 'Referrer-Policy: no-referrer-when-downgrade' veya 'same-origin' gibi uygun bir başlık ekleyin."
            },
            "Permissions-Policy": {
                "description": "Tarayıcı özelliklerine (kamera, mikrofon vb.) web sayfasının erişimini kontrol eder.",
                "severity": "Low",
                "recommendation": "İhtiyaçlarınıza göre uygun bir 'Permissions-Policy' başlığı ekleyin. Örneğin, 'Permissions-Policy: geolocation=(), microphone=()'."
            }
        }

        found_vulnerabilities = []
        
        for header, details in security_headers.items():
            if header not in headers:
                logging.warning(f"Zafiyet Tespit Edildi: Eksik HTTP Güvenlik Başlığı: {header}")
                found_vulnerabilities.append({
                    "name": f"Eksik Güvenlik Başlığı: {header}",
                    "severity": details["severity"],
                    "description": f"HTTP yanıt başlığında '{header}' bulunamadı. {details['description']}",
                    "recommendation": details["recommendation"],
                    "url": target_url
                })
            else:
                logging.debug(f"Başlık '{header}' bulundu: {headers[header]}")

        # Ayrıca, sunucu bilgisi başlığını kontrol et (Bilgi ifşası)
        if "Server" in headers:
            logging.info(f"Sunucu bilgisi başlığı bulundu: {headers['Server']}")
            found_vulnerabilities.append({
                "name": "Sunucu Bilgisi İfşası",
                "severity": "Low",
                "description": f"Web sunucusu, 'Server' başlığında yazılım versiyonunu ifşa ediyor: {headers['Server']}. Bu, potansiyel saldırganlara bilgi sağlayabilir.",
                "recommendation": "Sunucu yazılımınızın versiyon bilgisini gizleyin veya genel bir değer kullanın."
            })

        results["vulnerabilities"].extend(found_vulnerabilities)

    except requests.exceptions.RequestException as e:
        logging.error(f"HTTP başlıkları kontrol edilirken hata oluştu: {e}")
        results["vulnerabilities"].append({
            "name": "Ağ Bağlantı Hatası (HTTP Başlık Kontrolü)",
            "severity": "Critical",
            "description": f"Hedef URL'ye erişilemiyor veya ağ hatası oluştu: {e}",
            "url": target_url
        })

def check_robots_sitemap(target_url, results):
    """robots.txt ve sitemap.xml dosyalarının varlığını ve içeriğini kontrol eder."""
    logging.info("robots.txt ve sitemap.xml kontrol ediliyor...")
    base_url = target_url.rstrip('/') # URL sonundaki /'yi kaldır

    files_to_check = {
        "robots.txt": "robots.txt dosyası, arama motorlarının sitenizde hangi bölümleri taramasını ve taramamasını gerektiğini belirtir. Hassas dizinleri ifşa edebilir.",
        "sitemap.xml": "sitemap.xml dosyası, sitenizdeki tüm URL'leri listeler. Hassas veya gizli URL'lerin ifşa edilmesi potansiyel bir risk taşıyabilir."
    }

    for filename, description in files_to_check.items():
        file_url = f"{base_url}/{filename}"
        try:
            response = requests.get(file_url, timeout=5)
            if response.status_code == 200:
                logging.warning(f"Bilgi İfşası: {filename} dosyası bulundu: {file_url}")
                results["vulnerabilities"].append({
                    "name": f"Açık {filename} Dosyası",
                    "severity": "Low",
                    "description": f"{filename} dosyasına doğrudan erişim mümkün. Bu dosya hassas dizinleri veya URL'leri ifşa edebilir. {description}",
                    "recommendation": f"Eğer {filename} dosyası hassas bilgi içeriyorsa, bu bilgileri kaldırmayı veya erişimi kısıtlamayı düşünün.",
                    "url": file_url
                })
            else:
                logging.info(f"{filename} bulunamadı veya erişilemiyor (Status: {response.status_code})")
        except requests.exceptions.RequestException as e:
            logging.error(f"{filename} kontrol edilirken hata oluştu: {e}")
            # Bu durumda zafiyet olarak işaretlemeyiz, sadece loglarız.

# --- RAPORLAMA FONKSİYONU ---
def save_report(results, output_format, report_path):
    """Tarama sonuçlarını belirtilen formatta kaydeder."""
    report_filename = f"web_security_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    file_path = os.path.join(report_path, f"{report_filename}.{output_format}")

    if output_format == 'json':
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=4)
    elif output_format == 'html':
        # Basit bir HTML çıktısı oluşturma
        html_content = f"""
        <!DOCTYPE html>
        <html lang="tr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Web Güvenliği Tarama Raporu</title>
            <style>
                body {{ font-family: sans-serif; margin: 20px; background-color: #f4f7f6; color: #333; }}
                .container {{ max-width: 900px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                h1 {{ color: #0056b3; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
                h2 {{ color: #0056b3; margin-top: 20px; }}
                p {{ line-height: 1.6; }}
                .vulnerability {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px; background-color: #fefefe; }}
                .severity-Critical {{ color: #dc3545; font-weight: bold; }}
                .severity-High {{ color: #fd7e14; font-weight: bold; }}
                .severity-Medium {{ color: #ffc107; font-weight: bold; }}
                .severity-Low {{ color: #28a745; font-weight: bold; }}
                .severity-Info {{ color: #17a2b8; }}
                .recommendation {{ background-color: #e9ecef; padding: 10px; border-left: 5px solid #0056b3; margin-top: 10px; }}
                a {{ color: #007bff; text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Web Güvenliği Tarama Raporu</h1>
                <p><strong>Hedef:</strong> {results['target']}</p>
                <p><strong>Tarama Tipi:</strong> {results['scan_type']}</p>
                <p><strong>Zaman Damgası:</strong> {results['timestamp']}</p>
                
                <h2>Bulunan Zafiyetler: ({len(results['vulnerabilities'])})</h2>
                {"" if results['vulnerabilities'] else "<p>✅ Tarama tamamlandı, kritik zafiyet bulunamadı.</p>"}
                {"".join([f'''
                <div class="vulnerability">
                    <h3>{vuln['name']} (<span class="severity-{vuln['severity']}">{vuln['severity']}</span>)</h3>
                    <p><strong>Açıklama:</strong> {vuln['description']}</p>
                    <p><strong>URL:</strong> <a href="{vuln['url']}">{vuln['url']}</a></p>
                    <div class="recommendation">
                        <h4>Önerilen Düzeltme:</h4>
                        <p>{vuln.get('recommendation', 'Spesifik bir düzeltme önerisi bulunmamaktadır.')}</p>
                    </div>
                </div>
                ''' for vuln in results['vulnerabilities']])}
            </div>
        </body>
        </html>
        """
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    else: # txt formatı
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"Web Güvenliği Tarama Raporu\n")
            f.write(f"---------------------------\n")
            f.write(f"Hedef: {results['target']}\n")
            f.write(f"Tarama Tipi: {results['scan_type']}\n")
            f.write(f"Zaman Damgası: {results['timestamp']}\n\n")
            f.write(f"Bulunan Zafiyetler ({len(results['vulnerabilities'])}):\n")
            if not results['vulnerabilities']:
                f.write("Zafiyet bulunamadı.\n")
            for i, vuln in enumerate(results['vulnerabilities']):
                f.write(f"\n{i+1}. Zafiyet: {vuln['name']}\n")
                f.write(f"   Şiddet: {vuln['severity']}\n")
                f.write(f"   Açıklama: {vuln['description']}\n")
                f.write(f"   URL: {vuln['url']}\n")
                f.write(f"   Öneri: {vuln.get('recommendation', 'Spesifik bir düzeltme önerisi bulunmamaktadır.')}\n")
    logging.info(f"Rapor kaydedildi: {file_path}")

# --- ANA FONKSİYON ---
def main():
    args = parse_arguments()

    if args.verbose:
        # Detaylı loglama seviyesini ayarla
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info(f"Tarama başlatılıyor: Hedef = {args.target}, Tip = {args.scan_type}")

    # Rapor dizini oluşturma
    if not os.path.exists(args.report_path):
        os.makedirs(args.report_path)
        logging.info(f"Rapor dizini oluşturuldu: {args.report_path}")

    # Tarama sonuçlarını tutacak ana sözlük
    results = {
        "target": args.target,
        "scan_type": args.scan_type,
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities": []
    }

    # Temel bağlantı testi
    try:
        logging.info(f"Hedef URL'ye erişim kontrol ediliyor: {args.target}")
        response = requests.head(args.target, timeout=10, allow_redirects=True) # Sadece başlıkları al, hızlı kontrol
        if response.status_code < 400: # 2xx veya 3xx başarılı sayılır
            logging.info(f"Hedefe başarıyla bağlanıldı: {args.target} (Durum Kodu: {response.status_code})")
        else:
            logging.error(f"Hedefe bağlantı hatası veya beklenmedik durum kodu: {response.status_code}")
            results["vulnerabilities"].append({
                "name": "Bağlantı Hatası/Erişilebilirlik",
                "severity": "Critical",
                "description": f"Hedef URL'den {response.status_code} durum kodu döndü. Uygulama erişilebilir olmayabilir veya temel bir hata var.",
                "recommendation": "Hedef URL'nin doğru olduğundan ve uygulamanın çalıştığından emin olun.",
                "url": args.target
            })
            # Eğer bağlantı başarısızsa, diğer taramaları yapmaya gerek kalmaz
            save_report(results, args.output_format, args.report_path)
            logging.info("Tarama tamamlandı (bağlantı hatası nedeniyle erken sonlandı).")
            return

    except requests.exceptions.RequestException as e:
        logging.error(f"Hedefe bağlanırken kritik hata oluştu: {e}")
        results["vulnerabilities"].append({
            "name": "Ağ Bağlantı Hatası",
            "severity": "Critical",
            "description": f"Hedef URL'ye erişilemiyor: {e}. Ağ bağlantınızı veya hedef URL'yi kontrol edin.",
            "recommendation": "Ağ bağlantınızı kontrol edin ve hedef URL'nin doğru olduğundan emin olun.",
            "url": args.target
        })
        save_report(results, args.output_format, args.report_path)
        logging.info("Tarama tamamlandı (ağ hatası nedeniyle erken sonlandı).")
        return

    # --- TARAMA MANTIĞI ---
    # scan-type'a göre farklı kontrolleri çağırabiliriz
    if args.scan_type in ['quick', 'full']:
        check_http_headers(args.target, results)
        check_robots_sitemap(args.target, results)
        # Diğer "quick" tarama kontrolleri buraya eklenebilir

    if args.scan_type == 'full':
        # "full" tarama için daha kapsamlı kontroller buraya gelecek
        logging.info("Kapsamlı tarama (full scan) modunda daha fazla kontrol eklenecek...")
        # Örn: Basit form enjeksiyonu denemeleri, temel dizin taraması (robots.txt'ten farklı)
        pass # Şimdilik yer tutucu

    if args.scan_type == 'api':
        # "api" tarama için API odaklı kontroller buraya gelecek
        logging.info("API tarama modunda API güvenlik kontrolleri eklenecek...")
        pass # Şimdilik yer tutucu

    # Raporu kaydetme
    save_report(results, args.output_format, args.report_path)

    logging.info("Tarama tamamlandı.")

if __name__ == "__main__":
    main()