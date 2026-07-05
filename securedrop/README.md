# SecureDrop — Transfer File Terenkripsi E2E berbasis PKI

Versi ini **melepas total model TOFU** (Trust On First Use) lama dan menggantinya
dengan **PKI (Public Key Infrastructure)** sungguhan: ada **satu Server pusat** yang
berperan sebagai **CA (Certificate Authority) + Directory + Relay**, dan banyak **Klien**.

Kepercayaan antar-pengguna tidak lagi ditentukan dengan mencocokkan fingerprint
secara manual, melainkan lewat **verifikasi rantai sertifikat sampai ke Root CA**.
Kalau CA menandatangani sertifikat seseorang, identitasnya sah — tanpa langkah
"tandai aman" manual, tanpa mengetik IP/port.

---

## Arsitektur

```
        ┌──────────────────────────────────────────────┐
        │                SERVER PUSAT                    │
        │   (server.py — TCP + TLS, port 9000)           │
        │                                                │
        │   • CA         : menerbitkan sertifikat klien  │
        │   • Directory  : daftar pengguna + sertifikat  │
        │   • Relay      : kotak-surat terenkripsi        │
        │                  (store-and-forward)            │
        └───────────────▲───────────────▲────────────────┘
                        │ TLS           │ TLS
             mTLS + CSR │               │ mTLS + CSR
        ┌───────────────┴────┐   ┌──────┴─────────────┐
        │   KLIEN "bro"       │   │   KLIEN "salman"    │
        │   app.py :8080      │   │   app.py :8081      │
        │   (Web UI browser)  │   │   (Web UI browser)  │
        └────────────────────┘   └────────────────────┘
```

- **File selalu dienkripsi ujung-ke-ujung** (RSA-OAEP membungkus kunci sesi
  AES-256-GCM, ditambah **tanda tangan RSA-PSS** pengirim). Server **hanya melihat
  ciphertext** — tidak bisa membaca isi file.
- Pengiriman bersifat **store-and-forward**: pengirim mengunggah blob terenkripsi
  yang dialamatkan ke penerima; penerima mengunduhnya saat online. Inilah yang
  menghilangkan kebutuhan IP/port manual dan tahan NAT/firewall.

### Kenapa store-and-forward, bukan koneksi langsung?
Karena hanya dengan perantara server-lah kebutuhan **IP/port manual benar-benar
hilang**, penerima yang sedang offline tetap terlayani, dan server punya tempat
alami untuk mencatat **audit log**. Kerahasiaan tetap terjaga karena enkripsi
dilakukan **sebelum** data menyentuh server.

---

## Menjalankan

### 1. Pasang dependensi
```bash
pip install -r requirements.txt
```

### 2. Jalankan SERVER PUSAT (sekali saja)
```bash
python server.py
# mendengarkan di 0.0.0.0:9000, membuat Root CA di ./server_data/ca/
```

### 3. Jalankan KLIEN (Web UI) — satu per pengguna
```bash
python app.py
# buka http://localhost:8080  → daftar / masuk
```

Buka browser, **Daftar** (membuat kunci + CSR, lalu CA menandatangani sertifikat),
atau **Masuk** bila sudah punya akun.

---

## Demo 3 pengguna di satu komputer

Jalankan 1 server + 3 klien. Tiap klien cukup dibedakan lewat `SECUREDROP_DATA`
(folder identitas) dan `SECUREDROP_WEB_PORT` (port Web UI). **Semua klien menunjuk
ke server yang sama.**

```bash
# Terminal 1 — SERVER
python server.py

# Terminal 2 — klien "bro"
SECUREDROP_DATA=./data_bro    SECUREDROP_WEB_PORT=8080 python app.py

# Terminal 3 — klien "salman"
SECUREDROP_DATA=./data_salman SECUREDROP_WEB_PORT=8081 python app.py

# Terminal 4 — klien "try"
SECUREDROP_DATA=./data_try    SECUREDROP_WEB_PORT=8082 python app.py
```

Lalu buka `http://localhost:8080`, `:8081`, `:8082`, daftarkan `bro`, `salman`,
`try`, dan saling berkirim file. Di komputer berbeda, set
`SECUREDROP_SERVER_HOST=<ip-server>` pada tiap klien.

### Variabel lingkungan
| Variabel | Default | Keterangan |
|---|---|---|
| `SECUREDROP_SERVER_HOST` | `127.0.0.1` | alamat server pusat (klien) / bind (server) |
| `SECUREDROP_SERVER_PORT` | `9000` | port server pusat |
| `SECUREDROP_SERVER_DATA` | `./server_data` | data server (CA, blob, audit) |
| `SECUREDROP_DATA` | `./node_data` | data klien (identitas, outbox, hasil) |
| `SECUREDROP_WEB_PORT` | `8080` | port Web UI klien |
| `SECUREDROP_SECRET` | *(ganti!)* | kunci penandatangan cookie sesi |

---

## Fitur

1. **Riwayat & indikator keamanan** — tiap transfer menampilkan 4 aspek
   (Kerahasiaan, Integritas, Autentikasi, Nir-sangkal) dan garis waktu tahap
   `enkripsi → transfer → terima → verifikasi → dekripsi`, lengkap dengan timestamp,
   diperbarui otomatis.
2. **Transfer file** — semua file dienkripsi sebelum dikirim; pengirim bisa
   mengunduh salinan terenkripsinya; penerima bisa melihat metadata, mendekripsi,
   dan mengunduh versi terenkripsi bila perlu.
3. **Optimasi transfer** — streaming per potongan (hemat memori untuk file besar),
   dengan progress, kecepatan, durasi berjalan, dan total waktu transfer.
4. **Manajemen pengguna** — login username/password sebagai identitas, sementara
   komunikasi tetap memakai sertifikat/Public Key + E2E. Tersedia pula
   **Ekspor sertifikat** (`.sdbundle`).
5. **UI/UX** — antarmuka console modern dengan **mode terang & gelap**.
6. **Brankas** — enkripsi file untuk diri sendiri; saat membuka, **pilih sendiri
   folder tujuan** (Browse Folder).
7. **Audit log** — semua aktivitas dicatat otomatis (waktu, pengirim, penerima,
   nama file, ukuran, tahap, hasil verifikasi, akses tak sah) dengan halaman
   khusus dan **ekspor CSV/PDF**.

---

## Berkas utama

| Berkas | Peran |
|---|---|
| `server.py` | Server pusat: CA + Directory + Relay + audit |
| `pki.py` | Inti PKI: Root CA, CSR, penerbitan & **verifikasi rantai** |
| `crypto_core.py` | Enkripsi hibrida RSA-OAEP + AES-256-GCM + tanda tangan PSS |
| `container.py` | Format kontainer `.sdrop` (membawa sertifikat pengirim) |
| `client_core.py` | Sisi klien: identitas ber-sertifikat + komunikasi ke server |
| `wire.py` | Protokol berbingkai di atas TCP/TLS |
| `history.py` | Riwayat keamanan + audit + ekspor CSV/PDF (PDF tanpa dependensi) |
| `app.py` | Web UI klien (FastAPI) |
| `auth.py` | Sesi cookie + hash password PBKDF2 |
| `templates/`, `static/` | Antarmuka (HTML/CSS/JS), tema terang & gelap |
| `test_e2e.py`, `test_web.py` | Uji end-to-end inti & lapisan web |

## Mode S/MIME (opsional)

Selain transfer file, proyek ini juga menyertakan **implementasi S/MIME asli**
(tanda tangan + enkripsi email memakai CMS/PKCS#7 di atas sertifikat CA yang sama).
Lihat **`SMIME.md`** untuk konsep & cara pakai (`smime.py`, `smime_cli.py`,
`smime_demo.py`). Terbukti interoperabel dengan OpenSSL.

---

## Sifat & batasan keamanan (jujur)

- **Bootstrap kepercayaan CA.** Saat pertama daftar/masuk, klien mengambil
  sertifikat Root CA dari server melalui TLS yang belum terverifikasi (mirip TOFU,
  **hanya untuk sertifikat CA**). Di lingkungan nyata, distribusikan `ca_cert.pem`
  secara *out-of-band* (mis. lewat fitur ekspor/impor bundle) agar bootstrap ini
  ikut diamankan. Setelah punya CA, semua verifikasi berikutnya sepenuhnya PKI.
- **Metadata di server.** Karena audit log butuh nama file & ukuran, kedua metadata
  ini dikirim ke server dalam bentuk terbaca (isi file tetap terenkripsi). Bila
  metadata harus dirahasiakan juga, enkripsi header dapat ditambahkan.
- **"Browse Folder".** Aplikasi web menulis file di sisi server (mesin yang
  menjalankan klien), sehingga folder tujuan dipilih dengan **mengetik path** —
  bukan dialog folder OS.
- Ini proyek pembelajaran; untuk produksi tambahkan CRL/OCSP (pencabutan sertifikat),
  rate-limiting, dan penyimpanan kunci privat yang lebih kuat.
