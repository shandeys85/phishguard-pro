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

# Daftar kata kunci phishing yang diperluas seluas-luasnya (mencakup berbagai modus)
PHISHING_KEYWORDS = [
    # Modus Blokir & Keamanan Akun
    "akun diblokir",
    "akun ditangguhkan",
    "akun anda dibatasi",
    "aktivitas mencurigakan",
    "login mencurigakan",
    "pemulihan akun",
    "pulihkan akun",
    "reset password",
    "ubah kata sandi",
    "konfirmasi password",
    "password anda",
    # Modus Verifikasi & Pembaruan Data
    "verifikasi sekarang",
    "verifikasi akun",
    "segera konfirmasi",
    "update data",
    "pembaruan data",
    "lengkapi data",
    "isi data diri",
    "validasi data",
    "sinkronisasi data",
    "aktivasi ulang",
    # Modus Hadiah, Undian & Finansial
    "hadiah gratis",
    "pemenang undian",
    "pemenang utama",
    "selamat anda",
    "mendapatkan hadiah",
    "hadiah mobil",
    "hadiah uang",
    "klaim hadiah",
    "bonus saldo",
    "tarik tunai",
    "undian berhadiah",
    "pemberitahuan resi",
    # Modus Mendesak / Ancaman (Urgency)
    "urgently",
    "segera",
    "dalam waktu 24 jam",
    "batas waktu",
    "expired",
    "kedaluwarsa",
    "tindakan segera",
    "abaikan maka",
    # Instruksi Tindakan Berbahaya
    "klik link ini",
    "klik tautan",
    "scan qr",
    "scan barcode",
    "unduh aplikasi",
    "download apk",
    "instal aplikasi",
    "nomor telepon",
    "kirim otp",
    "kode otp",
    "masukkan pin",
]

# Daftar target populer yang sering dipalsukan (Typosquatting / Brand Impersonation)
POPULAR_BRANDS = [
    "google",
    "bca",
    "bri",
    "mandiri",
    "bni",
    "danamon",
    "cimb",
    "blu",
    "seabank",
    "jago",
    "dana",
    "ovo",
    "gopay",
    "shopeepay",
    "linkaja",
    "facebook",
    "instagram",
    "netflix",
    "paypal",
    "telkomsel",
    "indosat",
    "xl",
    "pln",
    "pajak",
    "kemenkeu",
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
    url = url.strip()
    if "[" in url and "](" in url:
      match = re.search(r"\((.*?)\)", url)
      if match:
        url = match.group(1)

    if not url.startswith("http://") and not url.startswith("https://"):
      url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]

    if not domain:
      return 0, ["Format URL tidak valid"], "Unknown"

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

    domain_parts = domain.split(".")
    if len(domain_parts) > 3:
      score += 20
      reasons.append(
          f"Peringatan: Struktur domain mencurigakan dengan banyak subdomain"
          f" ({len(domain_parts)} segmen)."
      )

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

    server_status = "Tidak Aktif / Unreachable"
    try:
      response = requests.get(url, timeout=5)
      server_status = (
          f"Aktif (HTTP Status: {response.status_code})"
          if response.status_code < 400
          else f"Merespons dengan Error ({response.status_code})"
      )
    except Exception:
      score += 15
      reasons.append(
          "Peringatan: Server target gagal dihubungi atau memblokir koneksi"
          " pengujian."
      )

    creation_date, error_msg = get_whois_data(domain)

    if isinstance(creation_date, list):
      creation_date = creation_date[0]

    if creation_date:
      if hasattr(creation_date, "tzinfo") and creation_date.tzinfo is not None:
        creation_date = creation_date.replace(tzinfo=None)

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


def analyze_email_content(text):
  text_lower = text.lower()
  found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]
  score = len(found_keywords) * 40
  reasons = [
      f"Ditemukan indikator pancingan psikologis: '{kw}'"
      for kw in found_keywords
  ]
  return min(score, 100), reasons


def analyze_sender_email(sender_email, text_content=""):
  """Fungsi analisis pengirim yang lebih agresif mendeteksi pencatutan merek"""
  score = 0
  reasons = []

  if not sender_email:
    return 0, reasons

  if "@" in sender_email:
    domain = sender_email.split("@")[1].lower()
    local_part = sender_email.split("@")[0].lower()
  else:
    return 50, ["Format alamat email pengirim tidak valid."]

  free_providers = [
      "gmail.com",
      "yahoo.com",
      "hotmail.com",
      "outlook.com",
      "ymail.com",
  ]

  if domain in free_providers:
    mentioned_brand = None
    for brand in POPULAR_BRANDS:
      if brand in local_part or brand in text_content.lower():
        mentioned_brand = brand
        break

    if mentioned_brand:
      score += 65
      reasons.append(
          f"BAHAYA BESAR: Pengirim menggunakan email publik gratis ('{domain}')"
          f" tetapi mencatut nama instansi/merek resmi ('{mentioned_brand}')."
          " Ini adalah ciri utama penipuan/spoofing!"
      )
    else:
      score += 25
      reasons.append(
          f"Peringatan: Pengirim menggunakan layanan email publik gratis"
          f" ('{domain}')."
      )

  for brand in POPULAR_BRANDS:
    if (
        brand in domain
        and not domain.endswith(f".{brand}.com")
        and not domain.endswith(f"{brand}.co.id")
    ):
      score += 50
      reasons.append(
          f"BAHAYA: Alamat email pengirim memalsukan merek populer ('{brand}')"
          f" pada domain '{domain}'."
      )
      break

  return min(score, 100), reasons


# --- TAMPILAN ANTARMUKA DASHBOARD STREAMLIT ---
st.markdown(
    "<h1 style='text-align: center;'>🛡️ PhishGuard Pro Enterprise</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<p style='text-align: center; color: gray;'>Sistem Deteksi Ancaman Phishing"
    " Berbasis Heuristik Teks, Spoofing Pengirim, dan Intelijen Jaringan"
    " Real-Time</p>",
    unsafe_allow_html=True,
)
st.divider()

tab1, tab2, tab3 = st.tabs(
    ["🌐 Analisis URL / Domain", "✉️ Analisis Pesan & Pengirim", "ℹ️ Tentang Sistem"]
)

with tab1:
  st.subheader("Pemeriksaan Keamanan Website & Domain")
  col1, col2 = st.columns([3, 1])

  with col1:
    target_url = st.text_input(
        "Masukkan URL atau Domain target:",
        placeholder="contoh: login-bca-verifikasi-update.com",
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

      if score >= 50:
        status_text = "BERBAHAYA (Potensi Phishing Tinggi)"
      elif score > 0:
        status_text = "MENCURIGAKAN (Waspada)"
      else:
        status_text = "AMAN"

      st.divider()

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
  st.subheader("Pemeriksaan Alamat Pengirim & Konten Pesan")

  sender_email = st.text_input(
      "Alamat Email Pengirim:",
      placeholder="contoh: bca.admin@gmail.com atau support@bca.co.id",
  )
  target_email = st.text_area(
      "Tempelkan teks pesan mencurigakan:",
      placeholder=(
          "Contoh: Selamat anda mendapatkan hadiah mobil silahkan isi data diri"
          "..."
      ),
  )

  if st.button("🔍 Analisis Email & Teks", use_container_width=True):
    if target_email or sender_email:
      score_sender, reasons_sender = analyze_sender_email(
          sender_email, target_email
      )
      score_content, reasons_content = analyze_email_content(target_email)

      total_score = min(score_sender + score_content, 100)
      all_reasons = reasons_sender + reasons_content

      if total_score >= 50:
        status_text = "🔴 BERBAHAYA (Indikasi Phishing Kuat)"
      elif total_score > 0:
        status_text = "🟡 MENCURIGAKAN"
      else:
        status_text = "🟢 AMAN / NORMAL"

      st.divider()

      t_col1, t_col2 = st.columns(2)
      t_col1.metric(
          label="Total Indeks Risiko",
          value=f"{total_score} / 100",
          delta="Bahaya" if total_score >= 50 else "Aman",
          delta_color="inverse",
      )
      t_col2.metric(label="Status Pesan", value=status_text)

      st.markdown("### 📋 Detail Analisis Pengirim & Konten:")

      if sender_email:
        st.markdown(f"**Analisis Pengirim (`{sender_email}`):**")
        if reasons_sender:
          for r in reasons_sender:
            if "BAHAYA" in r:
              st.error(f"  - {r}")
            else:
              st.warning(f"  - {r}")
        else:
          st.success("  - Domain pengirim terlihat normal/bersih.")

      st.markdown("**Analisis Isi Pesan:**")
      if reasons_content:
        for r in reasons_content:
          st.warning(f"  - {r}")
      else:
        st.success(
            "  - Tidak ditemukan kata kunci pancingan psikologis berbahaya."
        )
    else:
      st.warning(
          "Silakan masukkan setidaknya alamat email pengirim atau isi pesan."
      )

with tab3:
  st.subheader("Tentang PhishGuard Pro Enterprise")
  st.write(
      "Aplikasi ini dikembangkan untuk mendeteksi ancaman kejahatan siber"
      " berbasis rekayasa sosial (phishing) secara cepat dan akurat. Menggabungkan"
      " analisis alamat email pengirim (*spoofing check*), analisis semantik"
      " teks, inspeksi struktur domain anomali, penentuan *typosquatting*, serta"
      " verifikasi umur domain via protokol WHOIS secara *real-time*."
  )
  st.info(
      "💡 **Tips Keamanan:** Selalu periksa domain asli pengirim dan hindari"
      " mengklik tautan pada pesan yang mendesak tindakan instan."
  )
