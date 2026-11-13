# Torwell — uygulanabilirlik kararı

Güncel kapsam: Linux + Windows; macOS kapsamdan çıkarıldı. Aşağıdaki araştırma ilk üç platformlu değerlendirmeyi korur. Güncel uygulama planı: [IMPLEMENTATION.md](IMPLEMENTATION.md).

13 Kasım 2026. İki Haiku, bir Sonnet ve bir ucuz Codex görevinin çıktıları değerlendirildi; doğrulanmamış teknik iddialar resmi kaynaklarla düzeltildi.

## Sonuç

Rust çekirdek ve OpenTUI arayüzüyle Linux, Windows ve macOS hedefi teknik olarak makul. Ancak ağ yönlendirmesi platforma özgü olacak; aynı yetenekleri bütün cihazlarda garanti etmek doğru değil. Bu aşama kaynak/bağımlılık doğrulamasıdır, başarılı ürün testi değildir.

- Linux/Arch/CachyOS: nftables ve ayrı Tor süreciyle ilk prototip için önerilen hedef.
- Windows: imzalı Wintun, kullanıcı alanında TCP–SOCKS köprüsü ve WFP filtreleri aday mimari.
- macOS: Network Extension, platform entegrasyonu ve imzalı paketleme gerektirir. PF henüz doğrulanmış bir seçenek değildir.
- MAC: varsayılan kapalı, isteğe bağlı, adaptör bazında destek/ bilinmiyor/ desteklenmiyor durumu. Linux ve Windows için belgelenmiş yollar var; macOS'ta işletim sisteminin özel Wi-Fi adresi özelliği ile keyfi MAC atama ayrılmalı. Eski adres kadar eski profil politikası da geri yüklenmeli.

## OpenTUI doğrulaması

Upstream `dbebe5aa168ecc28f6772cfeb310e095f3b178b3` revizyonunda gerçek Rust bağlayıcıları var. JavaScript uygulama kodu zorunlu değil; OpenTUI'nin native render kütüphanesi gerekli.

İncelenen npm hazır paketinin revizyonu Rust bağlayıcılarıyla eşleşmedi; C başlık hash'leri de farklı. Derleme denemesi bu önkoşulda durduruldu. Cargo derlemesi, linkleme veya ekran testi çalışmadı. Çözüm adayı aynı revizyondan native kütüphaneyi kaynaktan derlemek ya da eşleşen hazır yayın kullanmak. Bu henüz doğrulanmadı.

## Önerilen sonraki kapsam

Önce eşleşen Rust/OpenTUI araç zinciriyle küçük bir arayüzü derleyip çalıştır. Ardından Arch VM içinde Tor başlat/durdur/durum, DNS/TCP yönlendirme, hata halinde dış trafiği engelleme ve geri alma uygula. Windows ve macOS için ayrı platform testleri geçilmeden destek ilan etme. MAC modülünü gerçek adaptör testleriyle etkinleştir.

Tor genel UDP/QUIC taşımaz. Tor IPv6 destekleyebilir; ilk sürümde IPv6 engellemek ürün kapsamı tercihidir. Ağ erişimi ve anonimlik aynı iddia değildir.

## Kanıtlar

- [Platform mimarisi ve kaynaklar](research/platform-routing.md)
- [MAC araştırması ve düzeltmeler](research/mac-address.md)
- [Rust/OpenTUI kaynak incelemesi](research/opentui-rust.md)
- [Derleme önkoşulu kontrolü ve engel](research/opentui-smoke.md)

Proje yalnızca yerelde hazırlandı ve T3'e kaydedildi. GitHub reposu açılmadı; yayın görünürlüğü henüz seçilmedi.
