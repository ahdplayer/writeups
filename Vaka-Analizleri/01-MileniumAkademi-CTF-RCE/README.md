# Milenium Akademi Red Team Lab — Writeup: Bir Zincirleme Reaksiyonun Anatomisi

**Operatör:** Ahmed Emin Aygören

**Hedef:** `mileniumakademi.online/ctf`

**Kazanılan Yetki:** RCE (Root)

**Kullanılan Araçlar:** Burp Suite Professional, ffuf, CyberChef, jwt.io

## 1. Keşif: Gizli Yorum ve robots.txt (01 Recon)

CTF sayfasına ilk giriş yaptığımızda bizi bir terminal ekranı karşılıyor. İlk ipucumuzu buradan alıyoruz: **Kaynak Kod İncelemesi (Source Code Inspection)!**

![Recon Terminali](./assets/Pasted%20image%2020260528224325.png)

Operasyon, ana sayfanın (`index.html`) statik analiziyle başladı. Burp Suite ile gelen yanıt (response) üzerinden kaynak kodu analizi yaptığımda, geliştiricinin bir Base64 dizisi bıraktığını gördüm.

![HTML](./assets/Pasted%20image%2020260528224539.png)

`QmFzaXQgYmlyIHJlY29uIHlhcC4gL3JvYm90cy50eHQga29udHJvbCBldC4=` dizisini çözümlemek için CyberChef'i açtım ve **From Base64** tarifini uyguladım.

Çıkan sonuç, bir başka kritik ipucuydu:

> _"Basit bir recon yap. /robots.txt kontrol et."_

`robots.txt` dosyasını açıp içeriğine baktığımızda `Disallow: /classified` girdisini görüyoruz. Böylece yeni hedefimiz kendini belli etmiş oldu.

## 2. Keşif: JS Analizi ve İlk Erişim (02 Keşif & 03 Credential)

![Classified Login Page](./assets/Pasted%20image%2020260528225453.png)

`/classified` dizininde yetkili personeller için hazırlanmış bir çalışan portalı yer alıyordu. Sistemin arkasındaki mantığı anlamak için bir kez daha kaynak kodlarına daldım. Sayfanın en alt kısmında gizlenmiş bir JavaScript kodu duruyordu:


```HTML
<script type="module">
  (function() {
    const props = ["value", "querySelector"];
    const operatorCodes = [111, 112, 101, 114, 97, 116, 111, 114];
    const passwordCodes = [114, 101, 100, 116, 101, 97, 109, 50, 48, 50, 54];

    function toString(codes) {
      return String.fromCharCode.apply(null, codes);
    }

    const loginForm = document.getElementById("loginForm");
    const loginResult = document.getElementById("loginResult");

    loginForm.addEventListener("submit", function(event) {
      event.preventDefault();

      const usernameInput = document[props[1]]("#username")[props[0]];
      const passwordInput = document[props[1]]("#password")[props[0]];

      const validUsername = toString(operatorCodes);
      const validPassword = toString(passwordCodes);

      if (usernameInput === validUsername && passwordInput === validPassword) {
        loginResult.className = "result success";
        loginResult.innerHTML = `
          Kimlik doğrulandı.<br><br>
          Token almak için API endpoint'ini kullan:<br>
          <code>POST /api/auth</code><br>
          <code>{"username":"` + validUsername + '","password":"' + validPassword + '"}</code>
        `;
        loginResult.style.display = "block";
      } else {
        loginResult.className = "result error";
        loginResult.textContent = "Hatalı kimlik bilgileri.";
        loginResult.style.display = "block";
      }
    });
  })();
</script>
```

Kodları incelediğimizde, statik (hardcoded) şekilde bir kullanıcı adı ve şifre bırakıldığını görüyoruz. Ayrıca bu kimlik bilgilerini (credentials) kullanabileceğimiz `POST /api/auth` endpoint'ini de keşfetmiş olduk.

Kodun içerisindeki ASCII dizilerini CyberChef'in **From Decimal** tarifi ile çözdüğümüzde:

- `111, 112, 101, 114, 97, 116, 111, 114` $\rightarrow$ **`operator`**

- `114, 101, 100, 116, 101, 97, 109, 50, 48, 50, 54` $\rightarrow$ **`redteam2026`**

Bu bilgilerle `/api/auth` endpoint'ine istek attık ve sunucudan gelen yanıt, düşük yetkili bir **JWT (JSON Web Token)** oldu:

![JWT Token](./assets/Pasted%20image%2020260528231234.png)

```JSON
{
  "message": "Hoşgeldin operator. Yetki seviyesi: employee",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJvcGVyYXRvciIsInJvbGUiOiJlbXBsb3llZSIsImlhdCI6MTc3OTgzMjA4MH0.nFD--aNVNTWBoCC719VTxhHZDnlrTZMByTx5-ah6oVQ"
}
```

## 3. API Enümerasyonu (Ffuf)

Elimdeki düşük yetkili token'ı hangi endpoint'lerde kullanabileceğimi öğrenmek adına `ffuf` ile kapsamlı bir dizin taraması başlattım:

Bash

```BASH
ffuf -u https://mileniumakademi.online/api/FUZZ \
     -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJvcGVyYXRvciIsInJvbGUiOiJlbXBsb3llZSIsImlhdCI6MTc3OTgzMjA4MH0.nFD--aNVNTWBoCC719VTxhHZDnlrTZMByTx5-ah6oVQ" \
     -w api_wordlist.txt -mc all -fc 404
```

Bu tarama sonucunda aşağıdaki endpoint'ler haritalandı:

- `/api/panel` (200 OK)
    
- `/api/files` (403 Forbidden)
    
- `/api/status` (405 Method Not Allowed)
    

Şu an için yetkimizin yettiği tek yer olan `/api/panel` üzerinden operasyona devam ediyoruz.

## 4. Yetki Yükseltme: JWT Manipülasyonu (04 Priv Esc)

Burp Repeater üzerinden `/api/panel` endpoint'ine bir `GET` isteği gönderdim:

![Admin Panel](./assets/Pasted%20image%2020260528232718.png)

Platformun kendi çalışanları için bıraktığı sistem notları arasında kritik bir veri sızıntısı yakalıyoruz: **JWT imzalama anahtarı (Secret Key)!**

> `k1r1lm4z_s1r_d3g1l`

Bu harika bir haber, çünkü artık kendi ürettiğimiz sahte token'ları bu anahtarla imzalayabileceğiz ve sunucu bunu kendisinin ürettiğini sanacak.

Öncelikle bulduğumuz secret'ın doğruluğunu teyit etmek için token'ı Burp Decoder veya `jwt.io` üzerine yapıştırıp alt kısma gizli kelimemizi giriyoruz:

![JWT Secret Key](./assets/Pasted%20image%2020260528234025.png)

Secret anahtarının doğru olduğunu onayladıktan sonra token düzenleme (forging) aşamasına geçiyoruz. Payload kısmındaki `"role": "employee"` değerini `"role": "admin"` olarak değiştiriyoruz. Sunucu bunu elindeki gizli anahtarla doğrulayacağı için artık tamamen meşru bir Admin token'ına sahibiz.

![Admin JWT Token](./assets/Pasted%20image%2020260528234329.png)

## 5. IDOR: Dosya Sisteminde Yatay Hareket (05 IDOR)

Daha önce enümerasyon yaparken keşfettiğimiz ama yetkimiz yetmediği için erişemediğimiz `/api/files` endpoint'ini yeni admin token'ımız ile tekrar zorluyoruz.

`GET /api/files` isteğini attığımızda sistem bize parametre ipucu içeren şöyle bir yanıt dönüyor:

```JSON
{
  "message": "Dosya ID'si belirt: /api/files?id=1",
  "available_ids": [1, 2, 3, 4, 5]
}
```

`?id` parametresiyle sistemdeki dosyalara doğrudan erişebildiğimizi fark ediyoruz (**Insecure Direct Object Reference**). Bize verilen `1,2,3,4,5` listesine sadık kalmayarak sınırları zorluyor ve `?id=0` parametresini deniyoruz. Karşımıza `root` kullanıcısına ait gizli notlar çıkıyor ve bizi `id=7` dosyasına yönlendiriyor.

`id=7` dosyasını okuduğumuzda sistemin bir sonraki halkasını kıracak olan o itirafı yakalıyoruz:

![IDOR Root Notes](./assets/Pasted%20image%2020260528235311.png)

> ⚠ BİLİNEN SORUN: Bu endpoint henüz input sanitization uygulanmadan üretime alındı. Düzeltme bekliyor.

## 6. Son Darbe: Remote Code Execution (06 RCE)

İç notlardan aldığımız bilgiye göre `/api/status` endpoint'i belirtilen hedefe ping atıyor ancak gelen girdileri temizlemiyor (**Lack of Input Sanitization**). Bu durum, gönderdiğimiz inputun doğrudan arka plandaki işletim sistemi kabuğuna (shell) gönderildiği anlamına gelir.

Eğer sisteme normal bir `{"target": "google.com"}` isteği atarsak masum bir ping çıktısı alırız. Ancak araya komut ayırıcı `;` (semicolon) karakterini ekleyip `{"target": "google.com; ls"}` şeklinde gönderirsek, mevcut çalışma dizininde (working directory) `flag.txt` dosyasının olduğunu görürüz.

![RCE Ping Command](./assets/Pasted%20image%2020260529000302.png)

Buradan sonrası çocuk oyuncağı. Hedefe `{"target": "google.com; cat flag.txt"}` payload'unu gönderiyoruz ve tam sistem yetkisiyle (RCE) bayrağı düşürüyoruz:

```JSON
{
  "output": "PING google.com (google.com): 56 data bytes\n64 bytes from google.com: icmp_seq=0 ttl=64 time=0.045 ms\n64 bytes from google.com: icmp_seq=1 ttl=64 time=0.038 ms\n--- google.com ping statistics ---\n2 packets transmitted, 2 packets received, 0% packet loss\n\nMLNM{r3d_t34m_k1ll_ch41n_t4m4ml4nd1}",
  "status": "executed"
}
```

Google'a atılan ping mesajının hemen altında sistem bayrağımız parıldıyor:

> **`MLNM{r3d_t34m_k1ll_ch41n_t4m4ml4nd1}`**

Operasyon başarıyla tamamlanmıştır! 🏁🔥