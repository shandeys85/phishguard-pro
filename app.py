import re
import whois
from datetime import datetime
from urllib.parse import urlparse
import streamlit as st

# Konfigurasi Halaman Streamlit
st.set_page_config(page_title="PhishGuard Pro", page_icon="🛡️", layout="centered")

# Daftar kata kunci phishing pada pesan
PHISHING_KEYWORDS = [
    "akun diblokir",
    "verifikasi sekarang",
    "hadiah gratis",
    "klik link ini",
    "segera konfirmasi",
    "password anda",
    "pemenang undian",
    "urgently",
]

# Daftar target populer yang sering dipalsukan (Typosquatting / Brand Impersonation)
POPULAR_BRANDS = [
    "google",
    "bca",
    "bri",
    "mandiri",
    "BNI",
    "dana",
    "ovo",
    "gopay",
    "facebook",
    "instagram",
    "netflix",
    "paypal",
]


def is_ip_address(domain):
  """Fungsi untuk mengecek apakah domain berupa alamat IP mentah"""
  ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
  return bool(ip_pattern.match(domain))


def real_domain_check(url):
  """Fungsi untuk mengecek umur domain asli di internet secara real-time"""
  try:
    if not url.startswith("http://") and not url.startswith("https://"):
      url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]

    if not domain:
      return 0, ["Format URL tidak valid"]

    score = 0
    reasons = []

    if is_ip_address(domain):
      score += 40
      reasons.append(
          "BAHAYA: URL menggunakan alamat IP mentah alih-alih nama domain"
          " resmi."
      )

    if parsed.scheme == "http":
      score += 25
      reasons.append(
          "Peringatan: Menggunakan protokol HTTP (tidak terenkripsi SSL)"
      )

    domain_lower = domain.lower()
    for brand in POPULAR_BRANDS:
      if (
          brand in domain_lower
          and not domain_lower.endswith(f".{brand}.com")
          and not domain_lower.endswith(f"{brand}.com")
      ):
        score += 35
        reasons.append(
            f"Peringatan: Terdeteksi upaya peniruan merek populer ('{brand}')"
            " pada domain."
        )
        break

    # Pengecekan Whois
    w = whois.whois(domain)
    creation_date = w.creation_date

    if isinstance(creation_date, list):
      creation_date = creation_date[0]

    if creation_date:
      age_days = (datetime.now() - creation_date).days
      reasons.append(
          f"Info Domain: Dibuat pada {creation_date.strftime('%Y-%m-%d')} (Umur:"
          f" {age_days} hari)"
      )

      if age_days < 30:
        score += 60
        reasons.append(
            f"BAHAYA: Domain ini sangat baru ({age_days} hari)! Sering digunakan"
            " untuk modus phishing."
        )
    else:
      score += 30
      reasons.append(
          "Peringatan: Tanggal registrasi domain disembunyikan/tidak valid."
      )

    return min(score, 100), reasons

  except Exception as e:
    return 50, [
        "Peringatan: Domain tidak ditemukan/tidak terdaftar di internet (Potensi"
        f" Domain Palsu). Error: {str(e)}"
    ]


def analyze_email(text):
  text_lower = text.lower()
  found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]
  score = len(found_keywords) * 35
  reasons = [
      f"Ditemukan kata pancingan psikologis: '{kw}'" for kw in found_keywords
  ]
  return min(score, 100), reasons


# Tampilan Antarmuka Streamlit
st.title("🛡️ PhishGuard Pro - Real-Time Threat Detector")
st.write(
    "Aplikasi deteksi dini ancaman phishing berbasis analisis URL real-time"
    " (WHOIS) dan heuristik teks."
)

menu = st.selectbox(
    "Pilih Menu Pengujian:",
    [
        "Cek URL / Website secara Real-Time",
        "Analisis Teks Pesan / Email Phishing",
    ],
)

if menu == "Cek URL / Website secara Real-Time":
  st.subheader("🌐 Pemeriksaan Domain & Keamanan URL")
  target_url = st.text_input(
      "Masukkan URL target (Contoh: google.com atau link mencurigakan):"
  )

  if st.button("Analisis URL"):
    if target_url:
      with st.spinner(
          "Sedang melacak umur domain secara live ke server internet..."
      ):
        score, reasons = real_domain_check(target_url)

      if score >= 50:
        st.error(f"Hasil Analisis: 🔴 BERBAHAYA (Skor Risiko: {score}/100)")
      elif score > 0:
        st.warning(f"Hasil Analisis: 🟡 MENCURIGAKAN (Skor Risiko: {score}/100)")
      else:
        st.success(f"Hasil Analisis: 🟢 AMAN (Skor Risiko: {score}/100)")

      st.markdown("**Detail Temuan:**")
      for r in reasons:
        st.write(f"- {r}")
    else:
      st.warning("Silakan masukkan URL terlebih dahulu.")

elif menu == "Analisis Teks Pesan / Email Phishing":
  st.subheader("✉️ Analisis Teks Pesan")
  target_email = st.text_area("Masukkan teks pesan email atau SMS:")

  if st.button("Analisis Teks"):
    if target_email:
      score, reasons = analyze_email(target_email)

      if score >= 50:
        st.error(f"Hasil Analisis: 🔴 BERBAHAYA (Skor Risiko: {score}/100)")
      elif score > 0:
        st.warning(f"Hasil Analisis: 🟡 MENCURIGAKAN (Skor Risiko: {score}/100)")
      else:
        st.success(f"Hasil Analisis: 🟢 AMAN (Skor Risiko: {score}/100)")

      st.markdown("**Detail Temuan:**")
      if reasons:
        for r in reasons:
          st.write(f"- {r}")
      else:
        st.write("- Tidak ada kata kunci mencurigakan yang ditemukan.")
    else:
      st.warning("Silakan masukkan teks pesan terlebih dahulu.")
