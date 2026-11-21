import html
import re

import joblib
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Cek Link Phishing", page_icon="🛡️", layout="centered")

# ================= GAYA TAMPILAN =================
st.markdown("""
<style>
.hero {
    background: linear-gradient(135deg, #1D4ED8 0%, #0EA5E9 100%);
    padding: 2rem 1.75rem;
    border-radius: 20px;
    margin-bottom: 1.5rem;
}
.hero-judul { color: white; font-size: 2rem; font-weight: 800; margin-bottom: .4rem; }
.hero-teks { color: #E0F2FE; font-size: 1.05rem; line-height: 1.5; }
.kartu {
    background: white;
    border: 1px solid #E2E8F0;
    border-radius: 16px;
    padding: 1rem 1.2rem;
    margin-bottom: .8rem;
    box-shadow: 0 1px 3px rgba(15, 23, 42, .06);
}
.kartu-judul { font-weight: 700; color: #1E293B; margin-bottom: .3rem; }
.kartu-isi { color: #475569; font-size: .95rem; line-height: 1.55; }
.hasil { border-radius: 20px; padding: 1.5rem; text-align: center; margin: 1rem 0 .6rem 0; }
.hasil-bahaya { background: #FEF2F2; border: 2px solid #FCA5A5; }
.hasil-aman { background: #F0FDF4; border: 2px solid #86EFAC; }
.hasil-ragu { background: #FFFBEB; border: 2px solid #FCD34D; }
.hasil-emoji { font-size: 3rem; line-height: 1.1; }
.hasil-judul { font-size: 1.45rem; font-weight: 800; margin: .5rem 0 .3rem 0; }
.hasil-bahaya .hasil-judul { color: #B91C1C; }
.hasil-aman .hasil-judul { color: #15803D; }
.hasil-ragu .hasil-judul { color: #B45309; }
.hasil-angka { color: #475569; }
.url-bedah {
    font-family: ui-monospace, Consolas, monospace;
    background: #0F172A;
    color: #CBD5E1;
    padding: 1rem 1.1rem;
    border-radius: 12px;
    word-break: break-all;
    font-size: .95rem;
}
.url-protokol { color: #94A3B8; }
.url-domain { color: #FDE68A; background: rgba(253, 230, 138, .15); padding: 0 4px; border-radius: 4px; font-weight: 700; }
.url-sisa { color: #93C5FD; }
.label-kecil { font-size: .85rem; color: #64748B; margin: .4rem 0 .6rem 0; }
</style>
""", unsafe_allow_html=True)


# ================= MODEL =================
@st.cache_resource
def muat_model():
    model = joblib.load("model_xgboost_url.pkl")
    fitur = joblib.load("fitur_url.pkl")
    return model, fitur


model, fitur_url = muat_model()


# ================= EKSTRAKSI FITUR (sama dengan notebook, sudah divalidasi) =================
def ekstrak_fitur(url, potong_akhir=True):
    url_hitung = url[:-1] if potong_akhir else url

    domain = url.split('://')[-1].split('/')[0].split(':')[0]
    tld = domain.split('.')[-1]
    panjang = len(url_hitung)

    inti = re.sub(r'^https?://', '', url_hitung)
    inti = re.sub(r'^www\.', '', inti)

    huruf = sum(c.isalpha() for c in inti)
    angka = sum(c.isdigit() for c in inti)
    spesial_lain = sum((not c.isalnum()) and c not in '=?&' for c in inti)
    obfuskasi = len(re.findall(r'%[0-9a-fA-F]{2}', url_hitung))

    return {
        'URLLength': panjang,
        'DomainLength': len(domain),
        'IsDomainIP': 1 if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', domain) else 0,
        'TLDLength': len(tld),
        'NoOfSubDomain': max(domain.count('.') - 1, 0),
        'HasObfuscation': 1 if obfuskasi > 0 else 0,
        'NoOfObfuscatedChar': obfuskasi,
        'ObfuscationRatio': obfuskasi / panjang,
        'NoOfLettersInURL': huruf,
        'LetterRatioInURL': huruf / panjang,
        'NoOfDegitsInURL': angka,
        'DegitRatioInURL': angka / panjang,
        'NoOfEqualsInURL': url_hitung.count('='),
        'NoOfQMarkInURL': url_hitung.count('?'),
        'NoOfAmpersandInURL': url_hitung.count('&'),
        'NoOfOtherSpecialCharsInURL': spesial_lain,
        'SpacialCharRatioInURL': spesial_lain / panjang,
        'IsHTTPS': 1 if url.startswith('https://') else 0,
    }


# ================= FUNGSI BANTU TAMPILAN =================
KATA_PANCINGAN = ["login", "verif", "update", "secure", "akun", "account",
                  "blokir", "hadiah", "bonus", "gratis", "promo", "undian", "klaim"]

SUFIKS_GANDA = {"co.id", "ac.id", "go.id", "or.id", "sch.id", "web.id", "my.id",
                "co.uk", "com.au", "co.jp", "com.br"}


def kartu(ikon, judul, isi):
    st.markdown(
        f'<div class="kartu"><div class="kartu-judul">{ikon} {judul}</div>'
        f'<div class="kartu-isi">{isi}</div></div>',
        unsafe_allow_html=True,
    )


def kartu_hasil(jenis, emoji, judul, keterangan):
    st.markdown(
        f'<div class="hasil hasil-{jenis}"><div class="hasil-emoji">{emoji}</div>'
        f'<div class="hasil-judul">{judul}</div>'
        f'<div class="hasil-angka">{keterangan}</div></div>',
        unsafe_allow_html=True,
    )


def pecah_url(url):
    protokol, sisa = url.split("://", 1)
    host = re.split(r"[/?#]", sisa, maxsplit=1)[0]
    ekor = sisa[len(host):]
    return protokol, host, ekor


def domain_utama(host):
    host = host.split(":")[0]
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return None
    bagian = host.split(".")
    if len(bagian) >= 3 and ".".join(bagian[-2:]) in SUFIKS_GANDA:
        return ".".join(bagian[-3:])
    return ".".join(bagian[-2:])


def tampil_bedah_url(url):
    protokol, host, ekor = pecah_url(url)
    st.markdown(
        f'<div class="url-bedah">'
        f'<span class="url-protokol">{html.escape(protokol)}://</span>'
        f'<span class="url-domain">{html.escape(host)}</span>'
        f'<span class="url-sisa">{html.escape(ekor)}</span></div>'
        f'<div class="label-kecil">⚪ protokol &nbsp;&nbsp; 🟡 nama domain &nbsp;&nbsp; 🔵 halaman / parameter</div>',
        unsafe_allow_html=True,
    )
    utama = domain_utama(host)
    if utama:
        st.markdown(
            f"🏠 Pemilik situs kemungkinan besar adalah **`{utama}`**. "
            "Ini bagian paling belakang dari nama domain, dan bagian inilah yang menentukan kamu sedang membuka situs siapa."
        )
    else:
        st.markdown("🏠 Link ini memakai **alamat IP**, jadi nggak ada nama pemilik situs yang bisa dibaca.")


def daftar_ciri(url, f):
    ciri = []
    if f['IsHTTPS'] == 0:
        ciri.append(("🔓", "Tidak memakai HTTPS",
                     "Data yang kamu ketik, misalnya password, dikirim tanpa enkripsi sehingga lebih mudah disadap. "
                     "Situs resmi zaman sekarang hampir selalu pakai HTTPS."))
    if f['IsDomainIP'] == 1:
        ciri.append(("🔢", "Memakai alamat IP, bukan nama domain",
                     "Situs resmi biasanya punya nama yang jelas. Deretan angka seperti <code>192.168.1.1</code> "
                     "sering dipakai untuk menyembunyikan identitas pemilik situs."))
    if f['URLLength'] > 50:
        ciri.append(("📏", f"Link cukup panjang ({f['URLLength']} karakter)",
                     "Link panjang bisa dipakai untuk menyembunyikan alamat asli di tengah teks yang membingungkan. "
                     "Tapi ingat, link panjang belum tentu berbahaya, contohnya halaman produk di toko online."))
    if f['NoOfDegitsInURL'] >= 5:
        ciri.append(("🧮", f"Banyak angka ({f['NoOfDegitsInURL']} angka)",
                     "Nama situs resmi jarang berisi deretan angka acak. Angka juga sering dipakai untuk meniru huruf, "
                     "misalnya <code>g00gle</code> (huruf o diganti angka 0)."))
    if f['NoOfOtherSpecialCharsInURL'] >= 5:
        ciri.append(("✳️", f"Banyak karakter spesial ({f['NoOfOtherSpecialCharsInURL']} karakter)",
                     "Banyak tanda seperti <code>-</code>, <code>_</code>, <code>.</code>, atau <code>/</code> "
                     "bisa bikin link terlihat rumit dan menyamarkan alamat aslinya."))
    if f['NoOfSubDomain'] >= 2:
        ciri.append(("🧩", "Banyak subdomain",
                     "Penipu sering menaruh nama situs terkenal di depan, misalnya "
                     "<code>namabank.co.id.situs-palsu.xyz</code>. Padahal pemilik aslinya ada di bagian paling belakang."))
    if f['HasObfuscation'] == 1:
        ciri.append(("🕶️", "Ada karakter yang disamarkan",
                     "Kode seperti <code>%20</code> atau <code>%2F</code> bisa dipakai untuk menyembunyikan karakter asli "
                     "supaya link sulit dibaca manusia."))
    if f['NoOfQMarkInURL'] > 0 or f['NoOfEqualsInURL'] > 0:
        ciri.append(("❓", "Mengandung parameter (tanda ? atau =)",
                     "Parameter itu normal di banyak situs, misalnya halaman pencarian. Tapi kalau muncul di link "
                     "dari orang tak dikenal, perhatikan baik-baik isinya."))
    kata = [k for k in KATA_PANCINGAN if k in url.lower()]
    if kata:
        ciri.append(("🎣", "Ada kata pancingan",
                     "Ditemukan kata: <b>" + ", ".join(kata) + "</b>. Kata seperti ini sering dipakai supaya kamu "
                     "panik atau tergiur, lalu buru-buru mengisi data."))
    return ciri


def isi_contoh(url):
    st.session_state["url"] = url


# ================= HEADER =================
st.markdown(
    '<div class="hero">'
    '<div class="hero-judul">🛡️ Cek Dulu, Klik Kemudian</div>'
    '<div class="hero-teks">Ragu sama sebuah link? Tempel di sini, biar model <i>machine learning</i> bantu menilai. '
    'Sekalian, yuk belajar mengenali ciri-ciri link phishing di bawah!</div>'
    '</div>',
    unsafe_allow_html=True,
)

# ================= BAGIAN 1: CEK LINK =================
st.text_input("Tempel link di sini 👇", key="url", placeholder="https://www.contoh.com")

st.caption("Belum punya link buat dicoba? Pakai contoh ini:")
contoh = [
    ("Google", "https://www.google.com"),
    ("Wikipedia", "https://www.wikipedia.org"),
    ("Alamat IP", "http://192.168.10.5/login/verify.php"),
    ("Link aneh", "http://login-verifikasi-akun.xyz/update.php?id=8821"),
]
kolom = st.columns(len(contoh))
for k, (nama, u) in zip(kolom, contoh):
    k.button(nama, on_click=isi_contoh, args=(u,))

st.write("")
if st.button("🔍 Periksa Sekarang", type="primary"):
    url = st.session_state["url"].strip()

    if not url:
        st.info("Eits, link-nya belum diisi nih 😄")
    elif not re.match(r"^https?://", url):
        st.warning("Tulis link lengkap dengan `http://` atau `https://` di depannya ya, misalnya `https://www.google.com`")
    else:
        f = ekstrak_fitur(url)
        X = pd.DataFrame([f])[fitur_url]
        peluang = float(model.predict_proba(X)[0][0])  # kolom 0 = phishing

        # Kalau link panjang, cek juga halaman utamanya (model lebih kuat di halaman utama)
        protokol, host, ekor = pecah_url(url)
        link_panjang = bool(ekor.strip("/"))
        peluang_utama = None
        if link_panjang:
            url_utama = f"{protokol}://{host}"
            X_utama = pd.DataFrame([ekstrak_fitur(url_utama)])[fitur_url]
            peluang_utama = float(model.predict_proba(X_utama)[0][0])

        if peluang >= 0.5 and link_panjang and peluang_utama < 0.5:
            kartu_hasil(
                "ragu", "🤔", "Perlu dicek lagi",
                f"Link lengkap: <b>{peluang:.1%}</b> phishing &nbsp;•&nbsp; "
                f"Halaman utama: <b>{peluang_utama:.1%}</b> phishing",
            )
            st.info(
                "Model menilai **link lengkapnya** mencurigakan, tapi **halaman utamanya** terlihat aman. "
                "Model ini lemah untuk link panjang, jadi bisa jadi ini **alarm palsu**. "
                "Pastikan nama domainnya memang situs yang kamu kenal sebelum mengisi data apa pun."
            )
        elif peluang >= 0.5:
            kartu_hasil(
                "bahaya", "🚨", "Hati-hati, link ini mencurigakan!",
                f"Peluang phishing menurut model: <b>{peluang:.1%}</b>",
            )
        else:
            kartu_hasil(
                "aman", "✅", "Link ini terlihat aman",
                f"Peluang phishing menurut model: <b>{peluang:.1%}</b>",
            )
        st.progress(peluang)

        st.markdown("#### 🔬 Bedah link ini")
        tampil_bedah_url(url)

        st.markdown("#### 🧐 Ciri yang terdeteksi")
        ciri = daftar_ciri(url, f)
        if ciri:
            for ikon, judul, isi in ciri:
                kartu(ikon, judul, isi)
        else:
            kartu("👍", "Nggak ada ciri mencurigakan yang menonjol",
                  "Tetap cek ulang nama domainnya ya, karena penipu juga bisa bikin link yang terlihat rapi.")
        st.caption("Daftar ini adalah pengamatan sederhana terhadap link, bukan penjelasan lengkap cara model mengambil keputusan.")

        if link_panjang:
            st.warning(
                "**Catatan:** model ini dilatih sebagian besar dengan link **halaman utama** situs "
                "(contoh: `https://www.namasitus.com`). Untuk link yang panjang, seperti halaman produk, "
                "hasil pencarian, atau artikel, hasilnya **bisa keliru**. Karena itu, halaman utamanya juga ikut dicek."
            )

# ================= BAGIAN 2: EDUKASI =================
st.divider()
st.markdown("## 🎓 Yuk, kenali phishing!")

st.markdown("### 🎣 Apa itu phishing?")
st.write(
    "Phishing berasal dari kata *fishing* (memancing). Penipu \"memancing\" kamu pakai umpan berupa pesan "
    "atau situs palsu yang mirip aslinya, supaya kamu mau menyerahkan data penting seperti password, PIN, "
    "kode OTP, atau nomor kartu."
)

st.markdown("### 🔬 Cara membaca link dengan benar")
st.write(
    "Trik yang paling sering dipakai: nama situs terkenal ditaruh di **depan**, padahal pemilik aslinya "
    "ada di **belakang**. Coba lihat contoh ini:"
)
tampil_bedah_url("https://bankku.co.id.verifikasi-akun.xyz/login")
st.info(
    "💡 **Rumus gampang:** cari tanda `/` pertama setelah `://`, lalu baca nama domain **dari kanan**. "
    "Di contoh atas, pemiliknya `verifikasi-akun.xyz`, bukan `bankku.co.id`!"
)

st.markdown("### 🚩 Ciri-ciri link phishing")
ciri_umum = [
    ("🔤", "Nama mirip tapi beda",
     "Huruf diganti atau ditambah, misalnya <code>g00gle.com</code> atau <code>tokoku-promo.shop</code>. "
     "Sekilas mirip, padahal beda pemilik."),
    ("🧩", "Nama terkenal di depan",
     "Contohnya <code>bankku.co.id.verifikasi-akun.xyz</code>. Pemilik aslinya ada di bagian paling belakang."),
    ("🔢", "Pakai alamat IP",
     "Misalnya <code>http://103.21.45.7/login</code>. Situs resmi hampir selalu pakai nama domain."),
    ("🔓", "Gembok bukan jaminan",
     "Gembok 🔒 (HTTPS) cuma berarti koneksinya terenkripsi, bukan berarti situsnya jujur. "
     "Di dataset proyek ini, <b>49.378 URL phishing</b> ternyata memakai HTTPS!"),
    ("✳️", "Panjang dan penuh simbol",
     "Deretan angka, tanda <code>-</code>, <code>%</code>, atau parameter acak bisa dipakai untuk menyamarkan alamat asli."),
    ("🎣", "Kata pancingan",
     "Kata seperti <i>verifikasi, blokir, hadiah, login, update</i> dipakai supaya kamu panik atau tergiur."),
    ("⏰", "Pesan yang bikin buru-buru",
     "\"Akun diblokir dalam 5 menit!\" Penipu ingin kamu panik sampai lupa mengecek."),
    ("🏷️", "Akhiran domain janggal",
     "Situs yang mengaku bank atau instansi tapi berakhiran <code>.xyz</code>, <code>.top</code>, atau "
     "<code>.click</code> patut dicurigai. Situs instansi pemerintah Indonesia memakai <code>.go.id</code>."),
]
kiri, kanan = st.columns(2)
for i, (ikon, judul, isi) in enumerate(ciri_umum):
    with (kiri if i % 2 == 0 else kanan):
        kartu(ikon, judul, isi)

st.markdown("### ✅ Kebiasaan aman sebelum klik")
st.markdown(
    "- **Ketik sendiri** alamat situs resmi, atau buka lewat aplikasi resmi, daripada klik link dari pesan.\n"
    "- **Cek nama domain** pakai rumus baca dari kanan tadi.\n"
    "- **Jangan pernah bagikan kode OTP**, PIN, atau password ke siapa pun, termasuk yang mengaku petugas.\n"
    "- **Aktifkan verifikasi dua langkah (2FA)** di akun-akun penting.\n"
    "- **Tenang dulu.** Pesan yang bikin panik atau terlalu menggiurkan patut dicurigai."
)

st.markdown("### 🆘 Terlanjur klik atau isi data?")
st.markdown(
    "1. **Ganti password** akun yang terdampak secepatnya, lewat aplikasi atau situs resmi.\n"
    "2. Kalau yang bocor data bank atau kartu, **hubungi bank** lewat nomor resmi yang tertera di kartu "
    "atau aplikasinya, lalu minta blokir.\n"
    "3. **Simpan bukti**: screenshot pesan, link, dan bukti transfer.\n"
    "4. **Laporkan** lewat kanal resmi:\n"
    "    - Situs atau konten penipuan → [aduankonten.id](https://aduankonten.id)\n"
    "    - Rekening penipu → [cekrekening.id](https://cekrekening.id)\n"
    "    - Nomor HP penipu → [aduannomor.id](https://aduannomor.id)\n"
    "    - Penipuan layanan keuangan → Kontak OJK **157**"
)

# ================= BAGIAN 3: TENTANG =================
st.divider()
with st.expander("ℹ️ Tentang aplikasi ini"):
    st.markdown(
        "**Model:** XGBoost, dilatih dengan 18 fitur yang dihitung dari teks URL saja.\n\n"
        "**Dataset:** [PhiUSIIL Phishing URL Dataset (UCI)](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), "
        "235.370 URL setelah pembersihan.\n\n"
        "**Hasil pengujian** (data dibagi berdasarkan domain): akurasi 99,81%, recall phishing 99,58%.\n\n"
        "**Keterbatasan:** dataset memiliki bias pengumpulan data. Misalnya, seluruh URL legitimate berupa halaman "
        "utama dan memakai HTTPS. Karena itu, model lemah untuk link panjang. Untuk mengurangi alarm palsu, "
        "aplikasi juga mengecek halaman utama dari link yang panjang.\n\n"
        "**Dibuat oleh:** 231344049 - Marsya Eka Pratiwi Nugroho"
    )

st.caption("⚠️ Hasil ini hanya alat bantu, bukan jaminan. Tetap waspada sebelum memasukkan data pribadi di situs mana pun.")
