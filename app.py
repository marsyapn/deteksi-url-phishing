import re
import joblib
import pandas as pd
import streamlit as st

# ---------- Pengaturan halaman ----------
st.set_page_config(page_title="Cek URL Phishing", page_icon="🛡️", layout="centered")


# ---------- Muat model (sekali saja, lalu disimpan di cache) ----------
@st.cache_resource
def muat_model():
    model = joblib.load("model_xgboost_url.pkl")
    fitur = joblib.load("fitur_url.pkl")
    return model, fitur


model, fitur_url = muat_model()


# ---------- Ekstraksi fitur (sama dengan notebook, sudah divalidasi) ----------
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


# ---------- Ciri mencurigakan dalam bahasa sehari-hari ----------
def ciri_mencurigakan(f):
    ciri = []
    if f['IsHTTPS'] == 0:
        ciri.append("🔓 Tidak memakai **HTTPS**, sehingga koneksinya tidak terenkripsi")
    if f['IsDomainIP'] == 1:
        ciri.append("🔢 Memakai **alamat IP**, bukan nama domain biasa")
    if f['URLLength'] > 50:
        ciri.append(f"📏 URL cukup **panjang** ({f['URLLength']} karakter)")
    if f['NoOfDegitsInURL'] >= 5:
        ciri.append(f"🔢 Mengandung **banyak angka** ({f['NoOfDegitsInURL']} angka)")
    if f['NoOfOtherSpecialCharsInURL'] >= 5:
        ciri.append(f"✳️ Mengandung **banyak karakter spesial** ({f['NoOfOtherSpecialCharsInURL']} karakter)")
    if f['NoOfSubDomain'] >= 2:
        ciri.append("🧩 Memiliki **banyak subdomain** (banyak titik di nama domain)")
    if f['HasObfuscation'] == 1:
        ciri.append("🕶️ Ada **karakter yang disamarkan** (misalnya `%20`)")
    if f['NoOfQMarkInURL'] > 0 or f['NoOfEqualsInURL'] > 0:
        ciri.append("❓ Mengandung **parameter** (tanda `?` atau `=`)")
    return ciri


def isi_contoh(url):
    st.session_state["url"] = url


# ---------- Tampilan ----------
st.title("🛡️ Cek URL Phishing")
st.write(
    "Ragu sama sebuah link? Tempel di bawah ini, nanti model *machine learning* "
    "akan menilai apakah link tersebut mencurigakan."
)

st.text_input("Masukkan URL", key="url", placeholder="https://www.contoh.com")

st.caption("Atau coba salah satu contoh:")
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
periksa = st.button("🔍 Periksa URL", type="primary")

if periksa:
    url = st.session_state["url"].strip()

    if not url:
        st.info("Masukkan URL-nya dulu ya 😊")
    elif not re.match(r'^https?://', url):
        st.warning("Tulis URL lengkap dengan `http://` atau `https://` di depannya, misalnya `https://www.google.com`")
    else:
        f = ekstrak_fitur(url)
        X = pd.DataFrame([f])[fitur_url]
        peluang = float(model.predict_proba(X)[0][0])  # kolom 0 = phishing

        st.divider()
        if peluang >= 0.5:
            st.error("### ⚠️ Hati-hati! URL ini terindikasi **PHISHING**")
        else:
            st.success("### ✅ URL ini terlihat **AMAN**")

        st.metric("Peluang phishing menurut model", f"{peluang:.1%}")
        st.progress(peluang)

        st.subheader("Ciri yang terdeteksi pada URL")
        ciri = ciri_mencurigakan(f)
        if ciri:
            for c in ciri:
                st.markdown(f"- {c}")
        else:
            st.markdown("- Tidak ada ciri mencurigakan yang menonjol 👍")
        st.caption("Daftar ini adalah pengamatan sederhana terhadap URL, bukan penjelasan lengkap cara model mengambil keputusan.")

        domain = url.split('://')[-1].split('/')[0]
        sisa = url.split('://', 1)[1][len(domain):]
        if sisa.strip('/'):
            st.warning(
                "**Catatan:** model ini dilatih sebagian besar dengan URL **halaman utama** situs "
                "(contoh: `https://www.namasitus.com`). Untuk URL yang panjang, seperti halaman produk, "
                "hasil pencarian, atau artikel, hasilnya **bisa keliru**. Coba juga periksa alamat halaman utamanya."
            )

# ---------- Tentang aplikasi ----------
with st.expander("ℹ️ Tentang aplikasi ini"):
    st.markdown(
        """
**Model:** XGBoost, dilatih dengan 18 fitur yang dihitung dari teks URL saja.

**Dataset:** [PhiUSIIL Phishing URL Dataset (UCI)](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset),
235.370 URL setelah pembersihan.

**Hasil pengujian** (data dibagi berdasarkan domain): akurasi 99,81%, recall phishing 99,58%.

**Keterbatasan:** dataset memiliki bias pengumpulan data. Misalnya, seluruh URL legitimate berupa
halaman utama dan memakai HTTPS. Karena itu, akurasi tinggi di data uji belum tentu sama di dunia nyata.

**Dibuat oleh:** 231344049 - Marsya Eka Pratiwi Nugroho
        """
    )

st.caption("⚠️ Hasil ini hanya alat bantu, bukan jaminan. Tetap waspada sebelum memasukkan data pribadi di situs mana pun.")
