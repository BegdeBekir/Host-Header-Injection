# 🛡️ Host Header Injection (HHI) Scanner

Bu Python aracı, web uygulamalarında **Host Header Injection (HHI)** zafiyetlerini test etmek için geliştirilmiştir.  
Belirtilen hedef URL'ye farklı **Host** header payload’ları göndererek, yönlendirme (redirect), yansıma (reflection) ve HTTP durum kodlarını raporlar.

---

## ✨ Özellikler
- Çoklu payload desteği (varsayılan + özel liste dosyası)
- Çoklu thread ile hızlı tarama
- Redirect ve reflection tespiti
- JSON ve CSV formatında çıktı
- Timeout ve hata yakalama mekanizması

---

## 🔧 Kurulum

```bash
git clone https://github.com/kullanici/hhi-scanner.git
cd hhi-scanner
pip install -r requirements.txt
```

> 📌 Gerekli kütüphaneler:
> - `requests`

---

## 🚀 Kullanım

### Temel Kullanım
```bash
python hhi_scanner.py -u http://hedefsite.com
```

### Özel Payload Dosyası ile
```bash
python hhi_scanner.py -u https://target.com -p payloads.txt
```

### Thread Sayısı Belirterek
```bash
python hhi_scanner.py -u http://hedef.com -t 20
```

### Çıktı Dosyası Adını Belirleme
```bash
python hhi_scanner.py -u http://hedef.com -o scan_results
```

---

## 📂 Çıktılar

Tarama tamamlandığında sonuçlar **hem JSON hem CSV** olarak kaydedilir.

- `hhi_results.json`
- `hhi_results.csv`

### JSON Örneği
```json
[
    {
        "payload": "evil.com",
        "status": 200,
        "redirected": false,
        "reflected": true,
        "final_url": "http://hedefsite.com/"
    }
]
```

### CSV Örneği
```csv
payload,status,redirected,reflected,final_url
evil.com,200,False,True,http://hedefsite.com/
```

---

## ⚠️ Uyarı

Bu araç yalnızca **güvenlik testleri** ve **yetkili pentest çalışmaları** için kullanılmalıdır.  
İzinsiz kullanım **yasal sonuçlar** doğurabilir.

---

👨‍💻 Geliştirici: [Senin Adın]  
