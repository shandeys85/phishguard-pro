import streamlit as st
import whois
from datetime import datetime
from urllib.parse import urlparse

# --- KONFIGURASI HALAMAN WEB ---
st.set_page_config(page_title="PhishGuard Pro", page_icon="🛡️", layout="centered")

# --- DATABASE KATA KUNCI PHISHING ---
PHISHING_KEYWORDS = ["akun diblokir", "verifikasi sekarang", "hadiah gratis", "klik link ini", "segera konfirmasi", "password anda", "pemenang undian", "urgently"]

def real_domain_check(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        if not domain:
            return 0, ["Format URL tidak valid"]

        score = 0
        reasons = []

        if parsed.scheme == 'http':
            score += 25
            reasons.append("Peringatan: Menggunakan protokol HTTP (tidak terenkripsi SSL)")

        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            reasons.append(f"Info Domain: Dibuat pada {creation_date.strftime('%Y-%m-%d')} (Umur: {age_days} hari)")
            if age_days < 30:
                score += 60
                reasons.append(f"BAHAYA: Domain ini sangat baru ({age_days} hari)! Indikasi kuat phishing.")
        else:
            score += 30
            reasons.append("Peringatan: Tanggal registrasi domain disembunyikan/tidak valid.")

        return score, reasons
    except Exception as e:
        return 50, [f"Peringatan: Domain tidak terdaftar atau gagal di-lookup. (Error: {str(e)})"]

def analyze_email(text):
    text_lower = text.lower()
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]
    score = len(found_keywords) * 35
    reasons = [f"Ditemukan kata pancingan psikologis: '{kw}'" for kw in found_keywords]
    return min(score, 100), reasons

# --- TAMPILAN ANTARMUKA (UI) WEB STREAMLIT ---
st.title("🛡️ PhishGuard Pro")
st.subheader("Real-Time Cyber Security & Threat Detector")
st.write("Uji tautan website atau pesan email mencurigakan untuk mendeteksi potensi serangan *phishing* secara instan.")

# Pilihan Menu Tab di Web
menu = st.tabs(["🌐 Analisis URL (Live Domain)", "📧 Analisis Teks Pesan / Email"])

with menu[0]:
    st.markdown("### Pengecekan Keamanan URL")
    url_input = st.text_input("Masukkan URL Website (Contoh: https://google.com):", placeholder="http://...")
    
    if st.button("Analisis URL Sekarang"):
        if url_input:
            with st.spinner("Sedang melacak server dan umur domain secara live..."):
                score, reasons = real_domain_check(url_input)
                
            st.markdown("---")
            st.markdown("### Hasil Analisis:")
            if score >= 50:
                st.error(f"🔴 BERBAHAYA (Skor Risiko: {score}/100)")
            elif score > 0:
                st.warning(f"🟡 MENCURIGAKAN (Skor Risiko: {score}/100)")
            else:
                st.success(f"🟢 AMAN (Skor Risiko: {score}/100)")
                
            st.write("**Detail Temuan:**")
            for r in reasons:
                st.write(f"- {r}")
        else:
            st.warning("Mohon masukkan URL terlebih dahulu!")

with menu[1]:
    st.markdown("### Analisis Isi Pesan / Email")
    email_input = st.text_area("Masukkan teks pesan yang dicurigai:", placeholder="Contoh: Akun Anda diblokir, klik link ini...")
    
    if st.button("Analisis Pesan Sekarang"):
        if email_input:
            score, reasons = analyze_email(email_input)
            
            st.markdown("---")
            st.markdown("### Hasil Analisis:")
            if score >= 50:
                st.error(f"🔴 BERBAHAYA (Skor Risiko: {score}/100)")
            elif score > 0:
                st.warning(f"🟡 MENCURIGAKAN (Skor Risiko: {score}/100)")
            else:
                st.success(f"🟢 AMAN (Skor Risiko: {score}/100)")
                
            st.write("**Detail Temuan:**")
            if reasons:
                for r in reasons:
                    st.write(f"- {r}")
            else:
                st.write("- Tidak ditemukan kata kunci pancingan penipuan.")
        else:
            st.warning("Mohon masukkan teks pesan terlebih dahulu!")
