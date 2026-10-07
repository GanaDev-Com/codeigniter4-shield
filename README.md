<p align="center">
  <img src="docs/logo.svg" width="96" height="96" alt="Logo Ganadev Shield">
</p>

<h1 align="center">CodeIgniter 4 Shield</h1>

<p align="center">
  Firewall aplikasi untuk CodeIgniter 4 — memeriksa setiap permintaan yang masuk dan memblokir yang berbahaya sebelum sampai ke aplikasi Anda.
</p>

<p align="center">
  <a href="https://packagist.org/packages/ganadev/codeigniter4-shield"><img src="https://img.shields.io/packagist/v/ganadev/codeigniter4-shield?style=flat-square&label=packagist&color=22d3ee" alt="Versi di Packagist"></a>
  <a href="https://github.com/GanaDev-Com/codeigniter4-shield/actions/workflows/ci.yml"><img src="https://github.com/GanaDev-Com/codeigniter4-shield/actions/workflows/ci.yml/badge.svg" alt="Status CI"></a>
  <img src="https://img.shields.io/badge/PHP-%5E8.2-22d3ee?style=flat-square&logo=php&logoColor=white" alt="Butuh PHP 8.2 atau lebih baru">
  <img src="https://img.shields.io/badge/CodeIgniter-4.3%2B-22d3ee?style=flat-square&logo=codeigniter&logoColor=white" alt="Mendukung CodeIgniter 4.3+">
  <img src="https://img.shields.io/badge/Lisensi-MIT-22d3ee?style=flat-square" alt="Lisensi MIT">
</p>

---

## Apa ini?

Setiap aplikasi web punya dua pintu masuk. Satu untuk orang yang memang memakai aplikasi Anda, dan satu lagi yang terbuka untuk siapa saja di internet. Pintu kedua itulah yang berbahaya — setiap permintaan datang dari mana saja, dan ada orang yang sengaja membuatnya berbahaya.

**CodeIgniter 4 Shield** menjadi penjaga pintu kedua tersebut. Dia memeriksa setiap permintaan, lalu:

- **Meneruskan** permintaan biasa, seperti tidak ada apa-apa. Pengunjung asli tidak pernah terganggu.
- **Meminta bukti** ketika pola perilaku mencurigakan tapi belum tentu berbahaya — misalnya dengan captcha.
- **Memblokir** permintaan yang jelas merupakan serangan, dan mencatat semua kejadiannya ke database.

Bagian pentingnya: Shield bukan pengganti sistem keamanan Anda sendiri. Filter SQL, validasi input, `Filter Auth`, dan proteksi CSRF tetap milik Anda. Shield hanya menambahkan satu lapisan lagi di depannya.

### Di mana posisinya?

```
Cloudflare / Edge WAF  ->  WAF hosting / ModSecurity  ->  CI4 Shield  ->  Aplikasi Anda
```

Shield sebaiknya berada **di belakang** firewall yang lebih umum, bukan sebagai pengganti. Kalau hosting Anda sudah punya ModSecurity, keduanya saling melengkapi.

---

## Yang dilindungi

- **Percobaan membuka file rahasia.** Bot pemindai mencari `.env`, `.git/config`, `wp-config.php`, dan kredensial AWS untuk membocorkan password dan API key.
- **Path traversal.** Termasuk varian yang di-encode tiga kali seperti `%252e%252e/`, plus `/proc/self/environ` dan `/etc/passwd`.
- **Percobaan remote code execution.** Termasuk `php://input`, `auto_prepend_file`, file backup, dan file PHP yang disembunyikan di folder gambar atau upload.
- **SQL injection, XSS, LFI, dan command injection** — bukan hanya di alamat URL, tapi juga di isi request.
- **Bot yang mengaku-ngaku.** Bot resmi seperti Googlebot dan Bingbot dikenali lewat pemeriksaan DNS, jadi website Anda tetap bisa dibaca mesin pencari. Bot palsu yang hanya mengaku-ngaku dicatat dan diblokir.
- **Pengepungan endpoint login.** Terlalu banyak percobaan login dari satu alamat IP akan memicu challenge, sehingga brute-force tidak berhasil.
- **Penelusuran file.** Deretan permintaan yang berakhir 404 di seluruh situs, plus aktivitas otomatis dengan User-Agent mencurigakan seperti `sqlmap` atau `nikto`.

---

## Instalasi

```bash
composer require ganadev/codeigniter4-shield
```

Package ini menarik [`ganadev/shield-core`](https://github.com/GanaDev-Com/shield-core) secara otomatis, jadi tidak perlu memasangnya terpisah.

### Konfigurasi (opsional)

Konfigurasi bawaan sudah cukup untuk memulai. Kalau ingin menyesuaikan, buat `app/Config/Shield.php` yang extends `Ganadev\Shield\Codeigniter\Config\Shield`, lalu ubah propertinya di sana.

### Daftarkan service provider

Buka `app/Config/Events.php` dan daftarkan provider pada event `pre_system`:

```php
Events::on('pre_system', static function (): void {
    \Ganadev\Shield\Codeigniter\ShieldServiceProvider::register();
});
```

Satu baris ini mendaftarkan service Shield (engine, resolver, cache, challenge driver), filter firewall global, dan perintah CLI sekaligus. Panggilan berulang aman — provider membangun ulang service dari konfigurasi terkini.

> Tanpa baris ini Shield tetap berjalan dengan fallback internal, tapi filter firewall tidak otomatis terpasang dan perintah `php spark shield:*` tidak terdaftar.

### Jalankan migrations

```bash
php spark migrate --all
```

---

## Daftarkan Filter

Kalau Anda memakai `ShieldServiceProvider::register()` seperti di atas, filter firewall **sudah otomatis** terdaftar global — tidak perlu melakukan apa pun lagi.

Kalau memasang manual tanpa provider, buka `app/Config/Filters.php`, lalu daftarkan filter Shield **secara global** — posisinya menentukan segalanya:

```php
public $aliases = [
    'shield.firewall' => \Ganadev\Shield\Codeigniter\Filters\SecurityFirewallFilter::class,
];

public $globals = [
    'before' => [
        'shield.firewall',
    ],
];
```

Filter ini harus berjalan **sebelum** filter lain, setelah IP klien asli dibaca. Shield akan memberi tahu lewat log kalau posisinya bergeser.

Kalau hanya ingin melindungi sebagian route, daftarkan sebagai filter bernama lalu pakai di route yang diperlukan.

---

## Sebelum dipakai di produksi

Dua hal ini paling sering terlewat, dan keduanya membuat Shield tidak bekerja seperti yang Anda kira.

### 1. Harus ada `proxyIPs` kalau di belakang proxy

Kalau aplikasi Anda berada di belakang Cloudflare, reverse proxy, atau load balancer, dan `proxyIPs` belum dikonfigurasi, maka **setiap pengunjung akan terlihat datang dari satu alamat IP yang sama** — yaitu IP proxy. Akibatnya rate limit per-IP jadi tidak berguna, dan ban tidak pernah kena pada orang yang seharusnya.

Di `app/Config/App.php`:

```php
public $proxyIPs = [
    // Cloudflare IPv4
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    // Cloudflare IPv6
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];
```

> **Jangan pernah pakai `proxyIPs = '*'` atau `['*']`.** Bentuk itu mempercayai semua orang, sehingga penyerang bisa memalsukan alamat IP pada header dan lolos dari ban.

Kalau Anda tidak memakai Cloudflare, ganti dengan CIDR proxy Anda sendiri. Daftar resmi Cloudflare ada di <https://www.cloudflare.com/ips/>.

Cek apakah konfigurasi ini sudah benar:

```bash
php spark shield:health
```

### 2. Mode default hanya mencatat, belum memblokir

Supaya tidak mengagetkan siapa pun saat pertama dipasang, Shield mulai dalam mode `observe`: keputusan tetap dihitung dan dicatat, tapi request diteruskan seperti biasa. **Jadi secara bawaan, Shield belum memblokir apa pun.**

Agar blokir benar-benar dijalankan, atur:

```dotenv
SHIELD_MODE=enforce
```

Cara paling aman adalah naikkan bertahap. Biarkan di `observe` beberapa hari, pantau `php spark shield:report` untuk melihat apa yang sebenarnya terjadi, lalu naikkan ke `enforce` saat sudah yakin tidak ada pengguna sah yang ikut kena.

---

## Konfigurasi

Semua opsi ada di satu file: `app/Config/Shield.php`, dan setiap propertinya sudah diberi komentar penjelasan dalam bahasa Indonesia. Mulai dari situ — tidak perlu mengatur semuanya di awal.

Beberapa yang paling sering diubah:

| Properti | Untuk apa |
|---|---|
| `mode` | `observe` (catat saja) atau `enforce` (jalankan semua keputusan) |
| `sensitivePaths` | Path yang memicu deteksi brute-force, default `/login` dan `/admin/login` |
| `skipPaths` | Path yang bebas dari pemeriksaan body dan deteksi perilaku — berguna untuk endpoint M2M atau webhook yang isinya teks bebas |
| `allowlistHosts/Paths/Ips` | Host, IP, atau path yang **selalu** lolos. Hati-hati, ini benar-benar melewati semua proteksi |
| `challengeDriver` | `turnstile` (default), `recaptcha`, atau `null` (untuk testing) |
| `botMode` | `observe` (default, aman untuk SEO), `challenge`, atau `off` |

### Environment Variables

```env
SHIELD_ENABLED=true
SHIELD_MODE=observe
SHIELD_APP_ID=my-app
SHIELD_CHALLENGE=turnstile
SHIELD_TURNSTILE_SITE_KEY=your-site-key
SHIELD_TURNSTILE_SECRET_KEY=your-secret-key
```

---

## Perintah CLI

| Perintah | Fungsi |
|---|---|
| `php spark shield:health` | Cek apakah semua komponen siap dipakai |
| `php spark shield:report` | Ringkasan kejadian keamanan |
| `php spark shield:rules:list` | Daftar aturan yang aktif beserta skornya |
| `php spark shield:replay` | Jalankan ulang log kejadian nyata untuk menguji deteksi |
| `php spark shield:release` | Lepas ban satu alamat IP |
| `php spark shield:prune` | Bersihkan kejadian lama sesuai `retentionDays` |

`shield:prune` sudah dijadwalkan otomatis setiap hari, tapi host Anda tetap **wajib** menjalankan cron berikut:

```cron
* * * * * cd /path-ke-aplikasi && php spark shield:prune >> /dev/null 2>&1
```

Ada juga panel admin opsional untuk melihat laporan, mengelola ban, dan menelusuri event. Panel ini **default-nya nonaktif**, karena halaman tersebut menampilkan reputasi pengguna — dan wajib dibatasi dengan izin `admin.authorize` kalau diaktifkan.

---

## Keterbatasan yang diketahui

- **Permintaan tanpa route (404) tidak diperiksa.** CodeIgniter melempar `PageNotFoundException` ketika URI tidak cocok dengan route mana pun, dan hal itu terjadi sebelum filter `before` global sempat berjalan. Scanner yang membidik path tak dikenal (misalnya `/.env`) oleh karena itu tidak disentuh Shield. Untuk lapisan ini, andalkan WAF di depan (Cloudflare, ModSecurity) atau aturan `mod_rewrite` di server.

---

## Demo App

Untuk mencoba Shield secara langsung, gunakan demo app:

```bash
cd examples/codeigniter4-demo
composer install
php spark migrate --all
php spark serve
```

Demo app menyediakan route untuk testing:
- `GET /home` — normal route
- `GET /login` — sensitive path
- `POST /login` — form submission
- `GET /api/users` — API endpoint

---

## Dokumentasi

Dokumentasi lengkap ada di **[shield.ganadev.com](https://shield.ganadev.com)**:

| Halaman | Isi |
|---|---|
| [Instalasi](https://shield.ganadev.com/installation/) | Setup langkah demi langkah |
| [Konfigurasi](https://shield.ganadev.com/configuration/) | Semua kunci config beserta artifaknya |
| [Aturan](https://shield.ganadev.com/rules/) | Aturan bawaan dan paket injection |
| [Perilaku & Bot](https://shield.ganadev.com/bots/) | Verifikasi crawler dan dampaknya ke SEO |
| [Challenge & Trusted](https://shield.ganadev.com/challenge/) | Cara kerja captcha dan cookie trusted |
| [Ban & Reputasi](https://shield.ganadev.com/bans/) | Durasi ban, eskalasi, dan riwayat |
| [Admin & CLI](https://shield.ganadev.com/admin/) | Semua perintah Spark |

---

## Open Source

CodeIgniter 4 Shield adalah proyek **open source** berlisensi MIT. Kode dan dokumentasinya bebas dibaca, diubah, dan dipakai ulang.

Kami terbuka pada masukan dan revisi apa pun — laporan bug, usulan fitur, perbaikan dokumentasi, sampai pull request. Semua itu membantu Shield menjadi lebih baik untuk semua orang, dan tidak ada yang perlu izin lebih dulu.

- Laporkan bug lewat [Issues](https://github.com/GanaDev-Com/codeigniter4-shield/issues)
- Usulkan fitur lewat [Discussions](https://github.com/GanaDev-Com/codeigniter4-shield/discussions)
- Temukan celah keamanan lewat [Security Advisory](https://github.com/GanaDev-Com/codeigniter4-shield/security/advisories/new), jangan lewat Issues publik
- Koreksi dokumentasi lewat pull request langsung — sekecil apa pun tetap berharga

Sebelum contribute, jalankan dulu:

```bash
composer test        # Pest
composer analyse     # PHPStan
composer format-test # Pint
```

Ketiganya harus hijau sebelum pull request dikirim.

---

## Lisensi

MIT — © 2026 [Ganadev](https://ganadev.com) / PT Ganadev Multi Solusi
