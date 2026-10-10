"""
app.py

Password Security Auditing Toolkit — Main Streamlit Dashboard
-----------------------------------------------------------------
Educational, open-source, defensive-only password auditing suite.

SAFETY NOTE: This application performs NO live credential extraction
(no SAM/shadow access) and NO active network brute-forcing. All
analysis is offline, mathematical, and local to the browser session.
"""

import streamlit as st

from modules import analyzer, generator, estimator, report

st.set_page_config(
    page_title="Password Security Auditing Toolkit",
    page_icon="🔐",
    layout="wide",
)

# --------------------------------------------------------------------
# Session state init
# --------------------------------------------------------------------
if "last_analysis" not in st.session_state:
    st.session_state.last_analysis = None
if "last_crack_time" not in st.session_state:
    st.session_state.last_crack_time = None
if "last_wordlist" not in st.session_state:
    st.session_state.last_wordlist = None
if "last_wordlist_keyword" not in st.session_state:
    st.session_state.last_wordlist_keyword = None
if "include_raw_password_in_report" not in st.session_state:
    st.session_state.include_raw_password_in_report = False

# --------------------------------------------------------------------
# Sidebar navigation
# --------------------------------------------------------------------
st.sidebar.title("🔐 Password Audit Toolkit")
st.sidebar.caption("Educational · Offline · Defensive use only")

page = st.sidebar.radio(
    "Navigate",
    ["Strength Tester", "Dictionary Builder", "Report Generator", "About / Safety"],
)

st.sidebar.markdown("---")
st.sidebar.markdown(
    "**Safety guardrails**\n\n"
    "- No live OS credential access\n"
    "- No active network brute-forcing\n"
    "- All math is local & offline"
)

# --------------------------------------------------------------------
# Page: Strength Tester
# --------------------------------------------------------------------
if page == "Strength Tester":
    st.title("🧪 Password Strength Tester")
    st.write(
        "Enter a password to analyze its entropy, complexity, and "
        "estimated offline crack time. Nothing is sent anywhere — "
        "analysis happens locally in this session."
    )

    password = st.text_input("Password to test", type="password")
    show_plain = st.checkbox("Show password as plain text", value=False)
    if show_plain and password:
        st.code(password)

    if password:
        analysis = analyzer.calculate_score(password)
        crack_time = estimator.estimate_crack_time(analysis["entropy_bits"])

        st.session_state.last_analysis = analysis
        st.session_state.last_crack_time = crack_time

        col1, col2, col3 = st.columns(3)
        col1.metric("Security Score", f"{analysis['score']} / 100")
        col2.metric("Entropy", f"{analysis['entropy_bits']} bits")
        col3.metric("Est. Crack Time", crack_time["human_readable"])

        if analysis["is_common_weak"]:
            st.error(
                "⚠️ This password matches a known common/breached password. "
                "It should never be used."
            )
        elif analysis["score"] >= 80:
            st.success(f"Rating: {analysis['rating']}")
        elif analysis["score"] >= 60:
            st.warning(f"Rating: {analysis['rating']}")
        else:
            st.error(f"Rating: {analysis['rating']}")

        st.progress(min(analysis["score"], 100) / 100)

        st.subheader("Complexity Checklist")
        complexity = analysis["complexity"]
        labels = {
            "length_ok_12": "At least 12 characters",
            "length_ok_8": "At least 8 characters",
            "has_lowercase": "Contains lowercase letters",
            "has_uppercase": "Contains uppercase letters",
            "has_digit": "Contains digits",
            "has_symbol": "Contains symbols",
            "no_repeated_chars": "No repeated character runs (e.g. 'aaa')",
        }
        cols = st.columns(2)
        for i, (key, label) in enumerate(labels.items()):
            with cols[i % 2]:
                st.checkbox(label, value=complexity[key], disabled=True, key=f"cb_{key}")

        st.caption(
            f"Crack-time estimate assumes an offline attack at "
            f"{crack_time['assumed_hash_rate']:,} hashes/second against "
            f"an unsalted fast hash — a commonly cited illustrative GPU "
            f"benchmark. Real-world systems using salted slow hashes "
            f"(bcrypt/Argon2) would be far more resistant."
        )
    else:
        st.info("Start typing a password above to see live analysis.")

# --------------------------------------------------------------------
# Page: Dictionary Builder
# --------------------------------------------------------------------
elif page == "Dictionary Builder":
    st.title("📚 Auditing Dictionary Builder")
    st.write(
        "Generate a custom wordlist of likely password permutations from "
        "a base keyword (e.g. a company name, product name, or team name). "
        "Blue teams can use this OFFLINE against existing password hashes "
        "to find predictable, organization-related passwords before "
        "attackers do."
    )

    base_keyword = st.text_input("Base keyword (e.g. company or project name)")
    max_entries = st.slider("Maximum entries to generate", 50, 2000, 500, step=50)

    if st.button("Generate Wordlist", type="primary"):
        if base_keyword.strip():
            wordlist = generator.generate_wordlist(base_keyword, max_entries=max_entries)
            st.session_state.last_wordlist = wordlist
            st.session_state.last_wordlist_keyword = base_keyword
        else:
            st.warning("Please enter a base keyword first.")

    if st.session_state.last_wordlist:
        wordlist = st.session_state.last_wordlist
        st.success(f"Generated {len(wordlist)} candidate entries.")
        st.dataframe(
            {"Candidate Passwords": wordlist},
            use_container_width=True,
            height=400,
        )

        wordlist_text = "\n".join(wordlist)
        st.download_button(
            "⬇️ Download wordlist (.txt)",
            data=wordlist_text,
            file_name=f"{st.session_state.last_wordlist_keyword}_audit_wordlist.txt",
            mime="text/plain",
        )

# --------------------------------------------------------------------
# Page: Report Generator
# --------------------------------------------------------------------
elif page == "Report Generator":
    st.title("📄 Audit Report Generator")
    st.write(
        "Compile the most recent Strength Tester and Dictionary Builder "
        "results from this session into a downloadable Markdown report."
    )

    has_analysis = st.session_state.last_analysis is not None
    has_wordlist = bool(st.session_state.last_wordlist)

    if not has_analysis:
        st.warning(
            "No password analysis found in this session yet. Visit the "
            "**Strength Tester** tab and test a password first."
        )
    else:
        st.success("Found password analysis from this session.")
    if has_wordlist:
        st.success(
            f"Found a generated wordlist "
            f"({len(st.session_state.last_wordlist)} entries) from this session."
        )
    else:
        st.info(
            "No wordlist found — the report will exclude the wordlist "
            "section unless you generate one in **Dictionary Builder**."
        )

    st.session_state.include_raw_password_in_report = st.checkbox(
        "Include the raw tested password text in the report "
        "(leave unchecked to keep the report safe to share)",
        value=False,
    )

    if has_analysis and st.button("Generate Markdown Report", type="primary"):
        label = "Tested Password (session)"
        if st.session_state.include_raw_password_in_report:
            # Only included if the user explicitly opts in.
            raw_pw = st.session_state.get("_raw_password_cache", None)
            label = f"`{raw_pw}`" if raw_pw else label

        md_report = report.generate_markdown_report(
            password_label=label,
            analysis=st.session_state.last_analysis,
            crack_time=st.session_state.last_crack_time,
            wordlist=st.session_state.last_wordlist,
            wordlist_base_keyword=st.session_state.last_wordlist_keyword,
        )

        st.markdown("### Preview")
        st.markdown(md_report)

        st.download_button(
            "⬇️ Download Report (.md)",
            data=md_report,
            file_name="password_audit_report.md",
            mime="text/markdown",
        )

# --------------------------------------------------------------------
# Page: About / Safety
# --------------------------------------------------------------------
else:
    st.title("ℹ️ About This Toolkit")
    st.markdown(
        """
This is an **educational, open-source Password Security Auditing Toolkit**
built for students and blue-team defenders learning about password
hygiene, entropy, and credential risk.

### What it does
- Scores password strength using mathematical entropy + complexity rules
- Estimates theoretical offline brute-force crack time (pure math)
- Generates candidate wordlists for **offline** blue-team hash audits
- Produces a shareable Markdown audit report with policy recommendations

### What it deliberately does NOT do
- ❌ Does **not** extract live OS credentials (no Windows SAM, no
  `/etc/shadow`, no browser credential stores)
- ❌ Does **not** perform active network brute-forcing or authentication
  attempts against any live system or service
- ❌ Does **not** transmit entered passwords anywhere — all computation
  is local to this Streamlit session

### Intended use
Security students practicing entropy/complexity analysis, and blue
teams who want to audit their **own** organization's already-held,
properly-authorized password hashes **offline** for reuse of
predictable, guessable passwords — not to attack systems they don't
own or have authorization to test.
"""
    )
