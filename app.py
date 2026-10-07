from datetime import datetime
import re
from urllib.parse import urlparse
import requests
import streamlit as st
import whois

# Konfigurasi Halaman Streamlit
st.set_page_config(
    page_title="PhishGuard Pro - Enterprise Security",
    page_icon="🛡️",
    layout="wide",
)

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
    "update data",
    "pulihkan akun",
]

# Daftar target populer yang sering dipalsukan (Typosquatting / Brand Impersonation)
POPULAR_BRANDS = [
    "google",
    "bca",
    "bri",
    "mandiri",
    "bni",
    "dana",
    "ovo",
    "gopay",
    "facebook",
    "instagram",
    "netflix",
    "paypal",
    "telkomsel",
    "pln",
]


def is_ip_address(domain):
  """Fungsi untuk mengecek apakah domain berupa alamat IP mentah"""
  ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
  return bool(ip_pattern.match(domain))


@st.cache_data(show_spinner=False)
def get_whois_data(domain):
  """Fungsi cached untuk mengambil data WHOIS agar performa lebih cepat"""
  try:
    w = whois.whois(domain)
    return w.creation_date, None
  except Exception as e:
    return None, str(e)


def real_domain_check(url):
  """Fungsi komprehensif untuk memeriksa keamanan URL"""
  try:
    if not url.startswith("http://") and not url.startswith("https://"):
      url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]

    if not domain:
      return 0, ["Format URL tidak valid"], "Unknown"

    score = 0
    reasons = []

    # 1. Cek apakah menggunakan alamat IP mentah
    if is_ip_address(domain):
      score += 40
      reasons.append(
          "BAHAYA: URL menggunakan alamat IP mentah alih-alih nama domain"
          " resmi."
      )

    # 2. Cek protokol HTTP vs HTTPS
    if parsed.scheme == "http":
      score += 25
      reasons.append(
          "Peringatan: Menggunakan protokol HTTP (tidak terenkripsi SSL)"
      )

    # 3. Anomali Subdomain (Contoh: bca.co.id.situs-penipu.com)
    domain_parts = domain.split(".")
    if len(domain_parts) > 3:
      score += 20
      reasons.append(
          f"Peringatan: Struktur domain mencurigakan dengan banyak subdomain"
          f" ({len(domain_parts)} segmen)."
      )

    # 4. Deteksi Typosquatting / Brand Impersonation
    domain_lower = domain.lower()
    for brand in POPULAR_BRANDS:
      if (
          brand in domain_lower
          and not domain_lower.endswith(f".{brand}.com")
          and not domain_lower.endswith(f"{brand}.co.id")
          and not domain_lower.endswith(f"{brand}.com")
      ):
        score += 35
        reasons.append(
            f"Peringatan: Terdeteksi upaya peniruan merek populer ('{brand}')"
            " pada domain."
        )
        break

    # 5. Cek Status HTTP Website menggunakan requests
    server_status = "Tidak Aktif / Unreachable"
    try:
      response = requests.get(url, timeout=5)
      server_status = (
          f"Aktif (HTTP Status: {response.status_code})"
          if response.status_code < 400
        )
        f"Merespons dengan Error ({response.status_code})"
    except Exception:
      score += 15
      reasons.append(
          "Peringatan: Server target gagal dihubungi atau memblokir koneksi"
          " pengujian."
      )

    # 6. Cek Umur Domain via WHOIS (Cached)
    creation_date, error_msg = get_whois_data(domain)

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
          "Peringatan: Tanggal registrasi domain disembunyikan/tidak valid"
          f" ({error_msg or 'Whois kosong'})."
      )

    return min(score, 100), reasons, server_status

  except Exception as e:
    return 50, [
        "Peringatan: Gagal memproses analisis URL. Error:"
        f" {str(e)}"
    ], "Error"


def analyze_email(text):
  text_lower = text.lower()
  found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]
  score = len(found_keywords) * 35
  reasons = [
      f"Ditemukan kata pancingan psikologis: '{kw}'" for kw in found_keywords
  ]
  return min(score, 100), reasons


# --- TAMPILAN ANTARMUKA DASHBOARD STREAMLIT ---
st.markdown(
    "<h1 style='text-align: center;'>🛡️ PhishGuard Pro Enterprise</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<p style='text-align: center; color: gray;'>Sistem Deteksi Ancaman Phishing"
    " Berbasis Heuristik Teks dan Intelijen Jaringan Real-Time</p>",
    unsafe_allow_html=True,
)
st.divider()

# Gunakan layout Tab agar profesional
tab1, tab2, tab3 = st.tabs(
    ["🌐 Analisis URL / Domain", "✉️ Analisis Pesan Teks", "ℹ️ Tentang Sistem"]
)

with tab1:
  st.subheader("Pemeriksaan Keamanan Website & Domain")
  col1, col2 = st.columns([3, 1])

  with col1:
    target_url = st.text_input(
        "Masukkan URL atau Domain target:",
        placeholder="contoh: login-bca-verifikasi.com",
    )

  with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    analyze_btn = st.button("🔍 Analisis URL", use_container_width=True)

  if analyze_btn:
    if target_url:
      with st.spinner(
          "Melakukan investigasi DNS, WHOIS, dan status server live..."
      ):
        score, reasons, server_status = real_domain_check(target_url)

      # Tentukan Status Keamanan
      if score >= 50:
        status_text = "BERBAHAYA (Potensi Phishing Tinggi)"
        status_color = "red"
      elif score > 0:
        status_text = "MENCURIGAKAN (Waspada)"
        status_color = "orange"
      else:
        status_text = "AMAN"
        status_color = "green"

      st.divider()

      # Tampilkan Metric Dashboard
      m_col1, m_col2, m_col3 = st.columns(3)
      m_col1.metric(
          label="Skor Risiko Keamanan",
          value=f"{score} / 100",
          delta=(
              "Tinggi"
              if score >= 50
              else ("Sedang" if score > 0 else "Rendah")
          ),
          delta_color="inverse",
      )
      m_col2.metric(label="Status Klasifikasi", value=status_text)
      m_col3.metric(label="Status Jaringan Server", value=server_status)

      st.markdown("### 📋 Laporan Rinci Temuan:")
      for r in reasons:
        if "BAHAYA" in r:
          st.error(f"- {r}")
        elif "Peringatan" in r:
          st.warning(f"- {r}")
        else:
          st.info(f"- {r}")
    else:
      st.warning("Silakan masukkan URL target terlebih dahulu.")

with tab2:
  st.subheader("Pemeriksaan Konten Pesan / Email / SMS")
  target_email = st.text_area(
      "Tempelkan teks mencurigakan di sini:",
      placeholder=(
          "Contoh: Akun Anda diblokir, segera verifikasi data Anda di sini..."
      ),
  )

  if st.button("🔍 Analisis Teks", use_container_width=True):
    if target_email:
      score, reasons = analyze_email(target_email)

      st.divider()
      t_col1, t_col2 = st.columns(2)
      t_col1.metric(
          label="Indeks Risiko Teks",
          value=f"{score} / 100",
          delta="Bahaya" if score >= 50 else "Aman",
          delta_color="inverse",
      )
      t_col2.metric(
          label="Status Pesan",
          value=(
              "🔴 Terdeteksi Indikasi Phishing"
              if score >= 50
              else "🟢 Normal / Bersih"
          ),
      )

      st.markdown("### 📋 Detail Analisis Psikologis Teks:")
      if reasons:
        for r in reasons:
          st.warning(f"- {r}")
      else:
        st.success(
            "- Tidak ditemukan pola kata kunci rekayasa sosial atau pancingan"
            " psikologis berbahaya."
        )
    else:
      st.warning("Silakan masukkan teks pesan terlebih dahulu.")

with tab3:
  st.subheader("Tentang PhishGuard Pro Enterprise")
  st.write(
      "Aplikasi ini dikembangkan untuk mendeteksi ancaman kejahatan siber"
      " berbasis rekayasa sosial (phishing) secara cepat dan akurat. Menggabungkan"
      " teknik analisis semantik teks, inspeksi struktur domain anomali,"
      " pengecekan *typosquatting*, serta verifikasi umur domain via protokol"
      " WHOIS secara *real-time*."
  )
  st.info(
      "💡 **Tips Keamanan:** Jangan pernah mengklik tautan atau memasukkan data"
      " pribadi pada situs web yang terdeteksi memiliki skor risiko tinggi."
  )
