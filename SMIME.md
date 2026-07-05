# Konsep S/MIME di SecureDrop

**S/MIME** (Secure/Multipurpose Internet Mail Extensions) adalah standar untuk
**menandatangani** dan **mengenkripsi** pesan MIME memakai **sertifikat X.509**
dan format **CMS/PKCS#7**. Karena CA SecureDrop (`pki.py`) sudah menerbitkan
sertifikat X.509, sertifikat itu **langsung dipakai** untuk S/MIME yang **asli
dan interoperabel** — terbukti bisa diverifikasi & didekripsi oleh **OpenSSL**
(lihat `smime_demo.py`), dan formatnya sama dengan yang dipahami Outlook,
Thunderbird, serta Apple Mail.

## Bagaimana S/MIME memenuhi 4 aspek keamanan

| Aspek | Mekanisme S/MIME | Di kode |
|---|---|---|
| **Kerahasiaan** | `EnvelopedData`: kunci sesi AES-256-CBC dibungkus RSA ke sertifikat tiap penerima | `smime.encrypt()` |
| **Integritas** | `messageDigest` (SHA-256 konten) di dalam `SignedData` | `smime.verify_signed()` |
| **Autentikasi** | sertifikat penanda-tangan diverifikasi rantainya ke CA | `pki.verify_chain()` |
| **Nir-sangkal** | tanda tangan RSA pengirim atas `signedAttrs` | `smime.verify_signed()` |

## Alur "sign-then-encrypt" (standar S/MIME)

```
  pesan MIME (From/To/Subject + body + lampiran)
        │  sign  (kunci privat pengirim)
        ▼
   CMS SignedData   ── membawa konten + tanda tangan + sertifikat pengirim
        │  encrypt (sertifikat X.509 penerima)
        ▼
   CMS EnvelopedData
        │  bungkus MIME
        ▼
   email .eml  (application/pkcs7-mime; smime-type=enveloped-data)
```

Membuka = kebalikannya: **dekripsi** amplop dengan kunci privat penerima →
**verifikasi** tanda tangan → **uraikan** MIME asli (body + lampiran).

> Catatan: sesuai standar, S/MIME **tidak menyembunyikan header** email
> (From/To/Subject tetap terlihat); yang dienkripsi adalah **isi & lampiran**.

## Memakai lewat CLI

```bash
python smime_cli.py init                 # buat Root CA (sekali)
python smime_cli.py issue alice          # terbitkan identitas + sertifikat S/MIME
python smime_cli.py issue bob

# Alice menyegel email + lampiran untuk Bob:
python smime_cli.py seal --from alice --to bob \
    --subject "Laporan Q3" --body "pesan rahasia" \
    --attach anggaran.csv --out pesan.eml

# Bob membuka (dekripsi + verifikasi) dan menyimpan lampiran:
python smime_cli.py open --as bob --in pesan.eml --save-dir ./keluar
```

Keluaran `open` menampilkan status **Kerahasiaan / Integritas / Autentikasi /
Nir-sangkal** dan identitas penanda-tangan yang terverifikasi via CA.

## Memakai lewat kode

```python
import pki, crypto_core as cc, smime

ca = pki.load_or_create_ca("./ca")
# terbitkan identitas S/MIME
priv, _ = cc.generate_keypair(2048)
cert = pki.load_cert(pki.sign_csr(ca, pki.make_csr(priv, "alice"),
                                  "alice", is_smime=True, email="alice@ex.id"))

eml = smime.seal_email("alice@ex.id", cert, priv,
        recipients=[("bob@ex.id", bob_cert)],
        subject="Halo", body="rahasia",
        attachments=[{"name":"a.txt","data":b"...","mime":"text/plain"}])

hasil = smime.open_email(eml, bob_cert, bob_key, ca.cert_pem)
print(hasil["security"])   # {confidentiality, integrity, authentication, non_repudiation, ...}
```

## Hubungan dengan relay SecureDrop

File `.eml`/`.p7m` hasil S/MIME **hanyalah byte terenkripsi** — server relay
(`server.py`) bisa menyimpan-dan-meneruskannya persis seperti blob transfer biasa,
karena server memang hanya melihat ciphertext. Jadi S/MIME bisa dipasang sebagai
**format muatan alternatif** di atas infrastruktur PKI + relay yang sudah ada,
tanpa mengubah server.

## Berkas

| Berkas | Peran |
|---|---|
| `smime.py` | Inti S/MIME: CMS sign/encrypt/decrypt + **verifier CMS pure-python** + lapisan MIME |
| `smime_cli.py` | Alat baris-perintah luring: init CA, terbitkan identitas, segel & buka email (file `.eml`) |
| `smime_demo.py` | Demo + uji end-to-end, termasuk **bukti interop OpenSSL** & uji negatif |
| `pki.py` | CA — kini bisa menerbitkan sertifikat S/MIME (`is_smime=True`, EKU emailProtection + SAN email) |

---

# Transport mTLS + objek S/MIME (dua lapis)

S/MIME mengamankan **objek** (pesannya sendiri, di mana pun ia berada). Itu berbeda
dari **mTLS** yang mengamankan **kanal** (koneksi hidup antar dua titik). Keduanya
saling melengkapi dan **memakai CA/sertifikat yang sama**. Bagian ini menyatukannya:
sepasang server–klien surat yang mengirim pesan **S/MIME** melalui koneksi **mTLS**.

```
   KANAL (mTLS)  ─ melindungi sambungan; hanya klien ber-sertifikat CA yang boleh operasi
   OBJEK (S/MIME)─ melindungi isi; server hanya melihat ciphertext (TLS "berhenti" di server,
                   tapi isi tetap terenkripsi karena sudah disegel S/MIME sebelum dikirim)
```

| Aspek | mTLS (kanal) | S/MIME (objek) |
|---|---|---|
| Melindungi | koneksi/sambungan | pesan itu sendiri |
| Berlaku | selama sesi hidup | selamanya, di disk/relay/transit |
| Server relay bisa baca isi? | ya (TLS berhenti di server) | **tidak** (hanya ciphertext) |
| Identitas dibuktikan saat | handshake | verifikasi tanda tangan |

## Menjalankan

```bash
# Terminal 1 — server (TCP+TLS dengan mTLS wajib untuk operasi terautentikasi)
python smime_server.py                       # default :9500

# Terminal 2 — Alice
python smime_mail_cli.py --data ./alice register --user alice --password a
python smime_mail_cli.py --data ./alice send --to bob \
       --subject "Anggaran Q3" --body "rahasia" --attach berkas.csv

# Terminal 3 — Bob
python smime_mail_cli.py --data ./bob register --user bob --password b
python smime_mail_cli.py --data ./bob inbox
python smime_mail_cli.py --data ./bob fetch --id <blob_id> --save-dir ./keluar --ack
```

`smime_mtls_demo.py` mendemonstrasikan **kedua lapis sekaligus** dan membuktikannya:
- TLS 1.3 dinegosiasikan (kanal terenkripsi), server mencatat CN klien via mTLS;
- blob tersimpan di server: **subjek terlihat, tetapi isi rahasia TIDAK terbaca**;
- Bob membuka via mTLS → keempat aspek C/I/A/N terverifikasi;
- **uji negatif kanal**: tanpa sertifikat klien → operasi ditolak; sertifikat dari
  **CA palsu → handshake mTLS gagal** (ditolak di lapisan kanal, sebelum aplikasi).

## Berkas transport

| Berkas | Peran |
|---|---|
| `smime_server.py` | Server surat: CA + Directory + kotak-surat, **TCP+TLS dengan mTLS**; hanya melihat ciphertext |
| `smime_client.py` | Klien: register/login, segel S/MIME lalu kirim via mTLS, ambil & buka |
| `smime_mail_cli.py` | CLI lintas-terminal untuk klien surat S/MIME-over-mTLS |
| `smime_mtls_demo.py` | Demo + uji: bukti kanal (mTLS) & objek (S/MIME), plus uji negatif mTLS |

## Kenapa mTLS OPSIONAL di server, bukan wajib total?

Saat pertama **register**, klien belum punya sertifikat — jadi tak mungkin
mempresentasikannya. Maka server memakai `ssl.CERT_OPTIONAL`: koneksi tanpa
sertifikat tetap boleh **hanya untuk** `get_ca`/`register`/`login`. Untuk operasi
lain (`directory`, `send`, `inbox`, `fetch`), server **mewajibkan** sertifikat
klien di lapisan aplikasi (baca CN dari `getpeercert`). Bila klien menyertakan
sertifikat tetapi dari CA lain, TLS menolaknya **saat handshake** (karena server
hanya memuat CA kita sebagai jangkar tepercaya). Jadi efektifnya: bootstrap terbuka,
selebihnya mTLS penuh.

## Batasan (jujur)

- **Verifikasi tanda tangan**: `cryptography` belum mengekspos verifikasi CMS,
  jadi di sini dipakai parser DER kecil untuk memverifikasi `SignedData`
  (RSA + SHA-256, dengan `signedAttrs`). Sudah dicocokkan dengan OpenSSL, tapi
  untuk produksi sebaiknya pakai pustaka S/MIME matang atau `openssl cms`.
- **Algoritma**: enkripsi konten AES-256-CBC (default aman CMS); tanda tangan
  RSA PKCS#1 v1.5 + SHA-256. Belum menangani RSA-PSS/ECDSA atau AES-GCM di CMS.
- **Pencabutan**: belum ada CRL/OCSP (sama seperti bagian PKI utama).
