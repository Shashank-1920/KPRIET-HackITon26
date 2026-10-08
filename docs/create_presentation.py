import sys
import collections
import collections.abc
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

def build_shade_presentation(output_path):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Enterprise Clean Light Palette
    c_white = RGBColor(255, 255, 255)
    c_bg_light = RGBColor(248, 250, 252)       # Slate 50
    c_navy_header = RGBColor(15, 23, 42)      # Slate 900
    c_slate_text = RGBColor(71, 85, 105)      # Slate 600
    c_sapphire_blue = RGBColor(29, 78, 216)   # Blue 700 / Accent
    c_emerald_green = RGBColor(5, 150, 105)   # Emerald 600
    c_crimson_red = RGBColor(220, 38, 38)     # Red 600
    c_amber_warn = RGBColor(217, 119, 6)      # Amber 600
    c_card_bg = RGBColor(241, 245, 249)       # Slate 100
    c_card_border = RGBColor(203, 213, 225)   # Slate 300
    c_blue_tint = RGBColor(239, 246, 255)     # Blue 50
    c_red_tint = RGBColor(254, 242, 242)      # Red 50
    c_emerald_tint = RGBColor(236, 253, 245)  # Emerald 50
    c_amber_tint = RGBColor(254, 243, 199)    # Amber 50

    def add_slide_header(slide, title_text, category_tag="PROJECT S.H.A.D.E. | ACADEMIC & HACKATHON PROPOSAL"):
        tb = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.35))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.text = category_tag.upper()
        p.font.name = "Arial"
        p.font.size = Pt(9.5)
        p.font.bold = True
        p.font.color.rgb = c_sapphire_blue

        tb_title = slide.shapes.add_textbox(Inches(0.8), Inches(0.75), Inches(11.7), Inches(0.6))
        tf_title = tb_title.text_frame
        tf_title.word_wrap = True
        tf_title.margin_left = tf_title.margin_top = tf_title.margin_right = tf_title.margin_bottom = 0
        p_title = tf_title.paragraphs[0]
        p_title.text = title_text
        p_title.font.name = "Arial"
        p_title.font.size = Pt(21)
        p_title.font.bold = True
        p_title.font.color.rgb = c_navy_header

        line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.35), Inches(11.733), Inches(0.02))
        line.fill.solid()
        line.fill.fore_color.rgb = RGBColor(226, 232, 240)
        line.line.color.rgb = RGBColor(226, 232, 240)

    def add_card(slide, left, top, width, height, bg_color=c_card_bg, border_color=c_card_border):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color
        card.line.color.rgb = border_color
        card.line.width = Pt(1)
        return card

    # ==========================================
    # SLIDE 1: Title & The Core Problem Statement
    # ==========================================
    s1 = prs.slides.add_slide(blank_layout)
    add_slide_header(s1, "1. Executive Summary & Problem Statement")

    add_card(s1, Inches(0.8), Inches(1.5), Inches(11.733), Inches(2.2), c_blue_tint, c_sapphire_blue)
    tb_prob = s1.shapes.add_textbox(Inches(1.1), Inches(1.65), Inches(11.133), Inches(1.9))
    tf_prob = tb_prob.text_frame
    tf_prob.word_wrap = True
    p = tf_prob.paragraphs[0]
    p.text = "S.H.A.D.E. — SOVEREIGN HOST FOR AI DATA ENFORCEMENT"
    p.font.name = "Arial"
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = c_sapphire_blue
    p.space_after = Pt(4)

    p2 = tf_prob.add_paragraph()
    p2.text = (
        '"In the era of cloud AI, knowledge workers and developers continuously leak confidential credentials '
        'and Indian PII (Aadhaar, PAN, API keys) into third-party LLMs and cloud servers through unmonitored prompt exfiltration. '
        'Concurrently, commercial brokers aggregate exposed identity records without transparency. '
        'While India\'s DPDP Act 2023 grants statutory rights to data erasure, users lack automated tooling '
        'to intercept prompt leaks in-flight or formulate verifiable statutory takedowns."'
    )
    p2.font.name = "Arial"
    p2.font.size = Pt(12.5)
    p2.font.italic = True
    p2.font.color.rgb = c_navy_header
    p2.space_before = Pt(4)

    card_width = Inches(3.75)
    gap = Inches(0.24)
    c_y = Inches(3.95)
    c_h = Inches(3.0)

    # Card 1: Outbound Leaks
    add_card(s1, Inches(0.8), c_y, card_width, c_h, c_red_tint, c_crimson_red)
    tb = s1.shapes.add_textbox(Inches(0.95), c_y + Inches(0.15), card_width - Inches(0.3), c_h - Inches(0.3))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "1. Shadow AI Prompt Exfiltration"
    p.font.name = "Arial"
    p.font.size = Pt(12.5)
    p.font.bold = True
    p.font.color.rgb = c_crimson_red
    p.space_after = Pt(8)
    
    bullets = [
        "Knowledge workers copy-paste real Aadhaar, PAN, & API keys into AI prompts.",
        "Confidential client data & source code permanently logged on third-party cloud servers.",
        "Traditional antivirus is blind to human-generated prompt text."
    ]
    for b in bullets:
        bp = tf.add_paragraph()
        bp.text = "• " + b
        bp.font.name = "Arial"
        bp.font.size = Pt(10)
        bp.font.color.rgb = c_slate_text
        bp.space_after = Pt(5)

    # Card 2: Inbound Harvesting
    add_card(s1, Inches(0.8) + card_width + gap, c_y, card_width, c_h, c_amber_tint, c_amber_warn)
    tb = s1.shapes.add_textbox(Inches(0.95) + card_width + gap, c_y + Inches(0.15), card_width - Inches(0.3), c_h - Inches(0.3))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "2. Unchecked Identity Sprawl"
    p.font.name = "Arial"
    p.font.size = Pt(12.5)
    p.font.bold = True
    p.font.color.rgb = c_amber_warn
    p.space_after = Pt(8)
    
    bullets = [
        "Historical database breaches expose old passwords, emails, and phone numbers.",
        "Users have dozens of dormant 'zombie accounts' vulnerable to credential stuffing.",
        "Zero unified visibility into where personal metadata is currently circulating."
    ]
    for b in bullets:
        bp = tf.add_paragraph()
        bp.text = "• " + b
        bp.font.name = "Arial"
        bp.font.size = Pt(10)
        bp.font.color.rgb = c_slate_text
        bp.space_after = Pt(5)

    # Card 3: Statutory Vacuum
    add_card(s1, Inches(0.8) + (card_width + gap) * 2, c_y, card_width, c_h, c_emerald_tint, c_emerald_green)
    tb = s1.shapes.add_textbox(Inches(0.95) + (card_width + gap) * 2, c_y + Inches(0.15), card_width - Inches(0.3), c_h - Inches(0.3))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "3. The DPDP Enforcement Gap"
    p.font.name = "Arial"
    p.font.size = Pt(12.5)
    p.font.bold = True
    p.font.color.rgb = c_emerald_green
    p.space_after = Pt(8)
    
    bullets = [
        "India's DPDP Act 2023 grants statutory Right to Erasure (Section 12).",
        "Non-compliance with security safeguards carries fines up to Rs.250 Crore.",
        "Citizens lack automated legal tools to draft and serve verified takedown requisitions."
    ]
    for b in bullets:
        bp = tf.add_paragraph()
        bp.text = "• " + b
        bp.font.name = "Arial"
        bp.font.size = Pt(10)
        bp.font.color.rgb = c_slate_text
        bp.space_after = Pt(5)

    # ==========================================
    # SLIDE 2: Glimpse of the Solution
    # ==========================================
    s2 = prs.slides.add_slide(blank_layout)
    add_slide_header(s2, "2. Glimpse of the Solution — The Sovereign AI Gateway")

    add_card(s2, Inches(0.8), Inches(1.5), Inches(11.733), Inches(1.4), c_card_bg, c_sapphire_blue)
    tb_c = s2.shapes.add_textbox(Inches(1.0), Inches(1.6), Inches(11.333), Inches(1.2))
    tf_c = tb_c.text_frame
    tf_c.word_wrap = True
    p = tf_c.paragraphs[0]
    p.text = "THE PARADIGM SHIFT: AN ON-DEVICE SOVEREIGN AI PRIVACY HYPERVISOR"
    p.font.name = "Arial"
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = c_sapphire_blue
    p.space_after = Pt(4)

    p2 = tf_c.add_paragraph()
    p2.text = (
        "S.H.A.D.E. is a Local AI Privacy Gateway and Sentinel running natively on the user's host machine. "
        "It acts as a secure local airlock: AI-bound prompts from IDEs, developer scripts, and desktop tools are sanitized in-flight "
        "using mathematical Verhoeff checksums and context rules, swapping Indian PII with synthetic decoys before cloud transmission, "
        "and seamlessly re-hydrating responses locally."
    )
    p2.font.name = "Arial"
    p2.font.size = Pt(11)
    p2.font.color.rgb = c_navy_header

    pipe_y = Inches(3.15)
    step_w = Inches(2.7)
    step_gap = Inches(0.31)
    step_h = Inches(3.8)

    steps = [
        ("1. Local AI Airlock", c_crimson_red, c_red_tint, [
            "Apps, IDEs, and tools route AI requests to local proxy: 127.0.0.1:8000.",
            "Clipboard Sentinel provides context-aware floating HUD.",
            "Legitimate banking/KYC copy-paste is never blocked."
        ]),
        ("2. In-Flight Tokenization", c_sapphire_blue, c_blue_tint, [
            "Verhoeff algorithm + proximity context verifies Indian Aadhaar.",
            "PAN and API secrets detected via regex suites.",
            "Replaced with format-preserving synthetic decoys in ephemeral RAM."
        ]),
        ("3. Sanitized Cloud Query", c_amber_warn, c_amber_tint, [
            "External cloud LLM (OpenAI, Claude) receives ONLY synthetic decoys.",
            "Plaintext PII never leaves host machine.",
            "Zero cloud training exposure."
        ]),
        ("4. Transparent Re-hydration", c_emerald_green, c_emerald_tint, [
            "Streaming response returns to local S.H.A.D.E. gateway.",
            "Decoys replaced with original values from volatile RAM.",
            "User sees complete, uncorrupted response locally."
        ])
    ]

    for idx, (title, color, tint, b_list) in enumerate(steps):
        s_left = Inches(0.8) + (step_w + step_gap) * idx
        add_card(s2, s_left, pipe_y, step_w, step_h, tint, color)
        
        tb = s2.shapes.add_textbox(s_left + Inches(0.12), pipe_y + Inches(0.15), step_w - Inches(0.24), step_h - Inches(0.3))
        tf = tb.text_frame
        tf.word_wrap = True
        
        p = tf.paragraphs[0]
        p.text = title
        p.font.name = "Arial"
        p.font.size = Pt(11.5)
        p.font.bold = True
        p.font.color.rgb = color
        p.space_after = Pt(10)

        for b in b_list:
            bp = tf.add_paragraph()
            bp.text = "• " + b
            bp.font.name = "Arial"
            bp.font.size = Pt(9.5)
            bp.font.color.rgb = c_slate_text
            bp.space_after = Pt(5)

    # ==========================================
    # SLIDE 3: System Architecture (The 5 Sovereign Pillars)
    # ==========================================
    s3 = prs.slides.add_slide(blank_layout)
    add_slide_header(s3, "3. System Architecture — The 5 Core Sovereign Pillars")

    p_w = Inches(2.2)
    p_gap = Inches(0.18)
    p_y = Inches(1.55)
    p_h = Inches(5.45)

    pillars = [
        ("1. Sovereign AI Gateway", c_crimson_red, c_red_tint, [
            "Local Reverse Proxy on 127.0.0.1:8000.",
            "OpenAI & Anthropic API compatible.",
            "Proxies IDEs (VS Code, Cursor), tools, and scripts.",
            "In-flight prompt tokenization & streaming re-hydration.",
            "Zero raw PII leaves local machine."
        ]),
        ("2. Context-Aware DLP", c_sapphire_blue, c_blue_tint, [
            "Verhoeff Dihedral D5 mathematical checksum.",
            "Proximity Context Engine (4-4-4 spacing / Aadhaar anchors).",
            "PAN 4th-char taxpayer entity validation.",
            "API keys (OpenAI, AWS) & banking (UPI/IFSC) regex.",
            "Ephemeral in-memory vault (RAM-only)."
        ]),
        ("3. Local Breach Radar", c_amber_warn, c_amber_tint, [
            "K-Anonymity cryptographic model.",
            "Transmits only 5-character SHA-1 prefix to breach API.",
            "Local suffix matching on host CPU.",
            "Illustrative Risk Score (72/100 benchmark).",
            "Zero credential disclosure."
        ]),
        ("4. DPDP Statutory Studio", c_emerald_green, c_emerald_tint, [
            "Statutory Section 12(1) & 12(3) Right to Erasure.",
            "Hardcoded legal templates (zero AI hallucination).",
            "Curated Indian fiduciary directory.",
            "Cites Act Schedule fines (up to Rs.250 Cr).",
            "Ready-to-dispatch drafts with local audit log."
        ]),
        ("5. Ambient Voice Sentinel", c_navy_header, c_card_bg, [
            "On-device wake-word: 'Hey Shade' (Porcupine).",
            "Vosk offline speech recognition on host CPU.",
            "Sub-40ms wake latency with <1.8% CPU usage.",
            "Real-time spoken leak exfiltration alerts.",
            "Hands-free control for security operations."
        ])
    ]

    for idx, (title, color, tint, b_list) in enumerate(pillars):
        x = Inches(0.8) + (p_w + p_gap) * idx
        add_card(s3, x, p_y, p_w, p_h, tint, color)
        
        top_bar = s3.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, p_y, p_w, Inches(0.08))
        top_bar.fill.solid()
        top_bar.fill.fore_color.rgb = color
        top_bar.line.color.rgb = color

        tb = s3.shapes.add_textbox(x + Inches(0.1), p_y + Inches(0.18), p_w - Inches(0.2), p_h - Inches(0.36))
        tf = tb.text_frame
        tf.word_wrap = True
        
        p = tf.paragraphs[0]
        p.text = title
        p.font.name = "Arial"
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = color
        p.space_after = Pt(10)

        for b in b_list:
            bp = tf.add_paragraph()
            bp.text = "• " + b
            bp.font.name = "Arial"
            bp.font.size = Pt(9)
            bp.font.color.rgb = c_slate_text
            bp.space_after = Pt(5)

    # ==========================================
    # SLIDE 4: Engineering Depth & Algorithms
    # ==========================================
    s4 = prs.slides.add_slide(blank_layout)
    add_slide_header(s4, "4. Engineering Depth — Algorithms & Mathematical Rigor")

    col_w = Inches(2.75)
    c_gap = Inches(0.24)
    y_pos = Inches(1.55)
    h_pos = Inches(5.45)

    eng_pillars = [
        ("1. Verhoeff + Context Engine", c_navy_header, [
            "Structural validation of Indian Aadhaar using Dihedral Group D5 matrix math.",
            "Iterative chain: c = d(c, p(i mod 8, digit)). Catches all adjacent transpositions.",
            "Proximity Context Anchor: Requires 4-4-4 spacing or keywords (Aadhaar, UID) to eliminate random 12-digit false positives.",
            "Deterministic, ultra-fast Python execution (<0.02ms)."
        ]),
        ("2. Regex Heuristic Suite", c_sapphire_blue, [
            "Evaluates PAN cards via standard format: [A-Z]{5}[0-9]{4}[A-Z]{1}.",
            "4th character taxpayer status verification (P, C, H, F).",
            "Catches secret API tokens: OpenAI (sk-...), AWS Access Keys (AKIA...).",
            "Contextual keyword entropy scanner (secret=, token=, pwd=)."
        ]),
        ("3. Ephemeral In-Memory Vault", c_emerald_green, [
            "In-memory session-scoped bidirectional map indexed by cryptographic hash.",
            "Replaces real values with format-preserving synthetic decoys.",
            "Session isolation: Keyed per conversation/tab; wiped on process termination.",
            "Local-First Guarantee: Plaintext is never written to disk or logs."
        ]),
        ("4. Statutory DPDP Synthesizer", c_amber_warn, [
            "Hardcoded statutory templates citing Section 12(1) and 12(3) of DPDP Act 2023.",
            "Cites Act's Schedule penalties (up to Rs.250 Cr for security safeguard failures).",
            "Auto-populates verified Grievance Officer details from curated catalog.",
            "Generates ready-to-dispatch drafts with local audit tracking."
        ])
    ]

    for idx, (title, color, b_list) in enumerate(eng_pillars):
        x = Inches(0.8) + (col_w + c_gap) * idx
        add_card(s4, x, y_pos, col_w, h_pos, c_card_bg, color)
        
        top_bar = s4.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y_pos, col_w, Inches(0.08))
        top_bar.fill.solid()
        top_bar.fill.fore_color.rgb = color
        top_bar.line.color.rgb = color

        tb = s4.shapes.add_textbox(x + Inches(0.15), y_pos + Inches(0.2), col_w - Inches(0.3), h_pos - Inches(0.4))
        tf = tb.text_frame
        tf.word_wrap = True
        
        p = tf.paragraphs[0]
        p.text = title
        p.font.name = "Arial"
        p.font.size = Pt(11.5)
        p.font.bold = True
        p.font.color.rgb = color
        p.space_after = Pt(10)

        for b in b_list:
            bp = tf.add_paragraph()
            bp.text = "• " + b
            bp.font.name = "Arial"
            bp.font.size = Pt(9.5)
            bp.font.color.rgb = c_slate_text
            bp.space_after = Pt(6)

    # ==========================================
    # SLIDE 5: User Interface & Live Demonstration Flow
    # ==========================================
    s5 = prs.slides.add_slide(blank_layout)
    add_slide_header(s5, "5. User Interface & Live Demonstration Flow")

    left_w = Inches(5.6)
    add_card(s5, Inches(0.8), Inches(1.55), left_w, Inches(5.45), c_card_bg, c_card_border)
    tb_ui = s5.shapes.add_textbox(Inches(1.05), Inches(1.75), left_w - Inches(0.5), Inches(5.0))
    tf_ui = tb_ui.text_frame
    tf_ui.word_wrap = True
    
    p = tf_ui.paragraphs[0]
    p.text = "SOVEREIGN WAR-ROOM HUD & CONTROLS"
    p.font.name = "Arial"
    p.font.size = Pt(12.5)
    p.font.bold = True
    p.font.color.rgb = c_sapphire_blue
    p.space_after = Pt(10)

    ui_points = [
        ("Sovereign War-Room HUD (React 19 + Tailwind):", "Light-mode dashboard displaying real-time illustrative risk gauge, breach exposure nodes, and gateway activity logs."),
        ("Local AI Gateway Interception Sandbox:", "Live interactive sandbox where test Aadhaar numbers and API keys are streamed through localhost:8000 to demonstrate in-flight tokenization."),
        ("Context-Aware Clipboard Toast Overlay:", "When an Aadhaar or secret is copied, a floating HUD allows user to 'Paste as Safe Decoy' or 'Send Real Value (KYC)'."),
        ("Ambient Voice Daemon ('Hey Shade'):", "Hands-free voice sentinel built on Porcupine wake-word + Vosk offline STT + Pyttsx3 TTS. Pitch as a voice control layer on privacy.")
    ]
    for title, desc in ui_points:
        p_t = tf_ui.add_paragraph()
        p_t.text = "• " + title
        p_t.font.name = "Arial"
        p_t.font.size = Pt(10)
        p_t.font.bold = True
        p_t.font.color.rgb = c_navy_header
        
        p_d = tf_ui.add_paragraph()
        p_d.text = desc
        p_d.font.name = "Arial"
        p_d.font.size = Pt(9)
        p_d.font.color.rgb = c_slate_text
        p_d.space_after = Pt(6)

    right_x = Inches(6.8)
    right_w = Inches(5.733)
    add_card(s5, right_x, Inches(1.55), right_w, Inches(5.45), c_blue_tint, c_sapphire_blue)
    tb_pitch = s5.shapes.add_textbox(right_x + Inches(0.25), Inches(1.75), right_w - Inches(0.5), Inches(5.0))
    tf_pitch = tb_pitch.text_frame
    tf_pitch.word_wrap = True
    
    p = tf_pitch.paragraphs[0]
    p.text = "3-MINUTE LIVE DEMONSTRATION SEQUENCE"
    p.font.name = "Arial"
    p.font.size = Pt(12.5)
    p.font.bold = True
    p.font.color.rgb = c_sapphire_blue
    p.space_after = Pt(10)

    demo_steps = [
        ("Minute 1: Live AI Gateway Prompt Interception", [
            "Send an AI query containing a valid-format test Aadhaar number.",
            "Show the outgoing payload: Cloud AI receives ONLY synthetic decoy.",
            "Show the incoming stream: Plaintext restored transparently locally."
        ]),
        ("Minute 2: Ambient Voice & Exposure Radar", [
            "Voice trigger: 'Hey Shade, scan identity exposure.'",
            "System responds with audible voice feedback.",
            "Dashboard displays illustrative risk score using k-anonymity breach lookup."
        ]),
        ("Minute 3: DPDP Statutory Takedown Requisition", [
            "Trigger: 'Hey Shade, formulate DPDP notice.'",
            "Generates verified Section 12 legal erasure requisition citing statutory penalties.",
            "Renders ready-to-dispatch notice with local audit trail."
        ])
    ]

    for title, b_list in demo_steps:
        p_t = tf_pitch.add_paragraph()
        p_t.text = title
        p_t.font.name = "Arial"
        p_t.font.size = Pt(10.5)
        p_t.font.bold = True
        p_t.font.color.rgb = c_navy_header
        p_t.space_before = Pt(4)
        
        for b in b_list:
            p_b = tf_pitch.add_paragraph()
            p_b.text = "  - " + b
            p_b.font.name = "Arial"
            p_b.font.size = Pt(9)
            p_b.font.color.rgb = c_slate_text

    # ==========================================
    # SLIDE 6: Technical Feasibility & 24-Hour Scope
    # ==========================================
    s6 = prs.slides.add_slide(blank_layout)
    add_slide_header(s6, "6. Technical Feasibility & 24-Hour Execution Blueprint")

    top_w = Inches(11.733)
    add_card(s6, Inches(0.8), Inches(1.55), top_w, Inches(2.2), c_card_bg, c_emerald_green)
    tb_f = s6.shapes.add_textbox(Inches(1.05), Inches(1.7), top_w - Inches(0.5), Inches(1.9))
    tf_f = tb_f.text_frame
    tf_f.word_wrap = True
    
    p = tf_f.paragraphs[0]
    p.text = "FEASIBILITY AUDIT: SCOPED EXECUTION FOR 4 B.TECH STUDENTS"
    p.font.name = "Arial"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = c_emerald_green
    p.space_after = Pt(6)

    f_points = [
        "Scoped Core Focus: Deep implementation of the 2 primary pillars (Local AI Gateway & DPDP Notice Generator).",
        "Pre-Built Unfair Advantage: Working voice wake-word daemon (Porcupine + Vosk) is operational, saving 6–8 hours.",
        "Zero Heavy GPU Dependencies: Regex, Verhoeff, and local proxy run on standard student laptop CPUs with <2% overhead.",
        "College Wi-Fi Failsafe: Dual-engine fallback switches to local deterministic cache if venue internet drops.",
        "Auditorium Noise Mitigation: On-screen quick-trigger simulation chips ensure testing continues even in loud presentation halls."
    ]
    for fp in f_points:
        p_b = tf_f.add_paragraph()
        p_b.text = "• " + fp
        p_b.font.name = "Arial"
        p_b.font.size = Pt(9.5)
        p_b.font.color.rgb = c_slate_text
        p_b.space_after = Pt(2)

    r_w = Inches(2.75)
    r_gap = Inches(0.24)
    r_y = Inches(3.95)
    r_h = Inches(3.0)

    roles = [
        ("Student 1: Gateway & Proxy", c_sapphire_blue, [
            "FastAPI reverse proxy.",
            "In-flight token replacement.",
            "In-memory session vault.",
            "Local auth token security."
        ]),
        ("Student 2: Detection & DLP", c_amber_warn, [
            "Verhoeff algorithm.",
            "Proximity context engine.",
            "PAN & API secret regex.",
            "Format-preserving decoys."
        ]),
        ("Student 3: DPDP & Web UI", c_emerald_green, [
            "Statutory notice templates.",
            "Curated fiduciary directory.",
            "React 19 War-Room HUD.",
            "Threat index visualization."
        ]),
        ("Student 4: Voice, Test & Pitch", c_navy_header, [
            "Porcupine voice daemon.",
            "50-item evaluation benchmark.",
            "Backup demo recording.",
            "Presentation & Q&A lead."
        ])
    ]

    for idx, (title, color, b_list) in enumerate(roles):
        rx = Inches(0.8) + (r_w + r_gap) * idx
        add_card(s6, rx, r_y, r_w, r_h, c_card_bg, color)
        
        tb = s6.shapes.add_textbox(rx + Inches(0.12), r_y + Inches(0.15), r_w - Inches(0.24), r_h - Inches(0.3))
        tf = tb.text_frame
        tf.word_wrap = True
        
        p = tf.paragraphs[0]
        p.text = title
        p.font.name = "Arial"
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = color
        p.space_after = Pt(8)

        for b in b_list:
            bp = tf.add_paragraph()
            bp.text = "• " + b
            bp.font.name = "Arial"
            bp.font.size = Pt(9.5)
            bp.font.color.rgb = c_slate_text
            bp.space_after = Pt(4)

    # ==========================================
    # SLIDE 7: Business Model & Market Viability
    # ==========================================
    s7 = prs.slides.add_slide(blank_layout)
    add_slide_header(s7, "7. Commercial Viability, Business Model & Competitive Edge")

    rev_w = Inches(3.75)
    rev_gap = Inches(0.24)
    rev_y = Inches(1.55)
    rev_h = Inches(2.4)

    rev_streams = [
        ("1. B2C Individual Tier", c_sapphire_blue, c_blue_tint, [
            "Free: Basic scan + 1 notice draft.",
            "Pro: Rs.149 - Rs.249 / month.",
            "Real-time AI gateway protection, breach radar, and recurring DPDP notice drafts."
        ]),
        ("2. B2B Developer / SME Teams", c_crimson_red, c_red_tint, [
            "Rs.499 / developer / month.",
            "Team AI Privacy Gateway for VS Code, Cursor, and internal LLM scripts.",
            "Prevents accidental corporate IP and customer PII exfiltration into cloud AI."
        ]),
        ("3. Competitive Differentiation", c_emerald_green, c_emerald_tint, [
            "vs. Microsoft Purview / Nightfall: Local-first architecture (zero cloud telemetry).",
            "vs. US Tools (DeleteMe/Incogni): Tailored specifically for Indian DPDP Act & Indian PII.",
            "Transparent in-flight re-hydration."
        ])
    ]

    for idx, (title, color, tint, b_list) in enumerate(rev_streams):
        rx = Inches(0.8) + (rev_w + rev_gap) * idx
        add_card(s7, rx, rev_y, rev_w, rev_h, tint, color)
        
        tb = s7.shapes.add_textbox(rx + Inches(0.15), rev_y + Inches(0.15), rev_w - Inches(0.3), rev_h - Inches(0.3))
        tf = tb.text_frame
        tf.word_wrap = True
        
        p = tf.paragraphs[0]
        p.text = title
        p.font.name = "Arial"
        p.font.size = Pt(11.5)
        p.font.bold = True
        p.font.color.rgb = color
        p.space_after = Pt(6)

        for b in b_list:
            bp = tf.add_paragraph()
            bp.text = "• " + b
            bp.font.name = "Arial"
            bp.font.size = Pt(9.5)
            bp.font.color.rgb = c_slate_text
            bp.space_after = Pt(4)

    bot_y = Inches(4.15)
    bot_w = Inches(11.733)
    bot_h = Inches(2.8)
    add_card(s7, Inches(0.8), bot_y, bot_w, bot_h, c_card_bg, c_sapphire_blue)

    tb_b = s7.shapes.add_textbox(Inches(1.05), bot_y + Inches(0.18), bot_w - Inches(0.5), bot_h - Inches(0.36))
    tf_b = tb_b.text_frame
    tf_b.word_wrap = True
    
    p = tf_b.paragraphs[0]
    p.text = "UNIT ECONOMICS & MARKET VALIDATION STRATEGY"
    p.font.name = "Arial"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = c_sapphire_blue
    p.space_after = Pt(6)

    econ_points = [
        "Edge-First Cost Structure: Regex, Verhoeff, and local proxy run on local CPU (Rs.0 compute cost). Estimated cloud API cost is ~Rs.20-Rs.30/user/month for notice drafting.",
        "Market Drivers: Companies fear non-compliance fines under DPDP Act (up to Rs.250 Cr for failing to maintain security safeguards against breaches).",
        "Target Customers: Indian tech teams, fintech developers, and knowledge workers using generative AI daily.",
        "Go-To-Market Validation Plan: Launch open-source developer proxy with waitlist for enterprise team management; validate with 10 pilot developer teams in Year 1.",
        "Clear Limitations Disclosed: Scoped to text-based AI prompt streams; mobile apps and encrypted binary uploads acknowledged on future roadmap."
    ]
    for ep in econ_points:
        p_b = tf_b.add_paragraph()
        p_b.text = "• " + ep
        p_b.font.name = "Arial"
        p_b.font.size = Pt(10)
        p_b.font.color.rgb = c_slate_text
        p_b.space_after = Pt(4)

    prs.save(output_path)
    print(f"Successfully generated updated PowerPoint: {output_path}")

if __name__ == '__main__':
    target_pptx_primary = r"c:\Users\Shashank\OneDrive\Desktop\KPRIET Hackathon\SHADE_Sovereign_Presentation.pptx"
    target_pptx_fallback = r"c:\Users\Shashank\OneDrive\Desktop\KPRIET Hackathon\SHADE_Presentation.pptx"
    build_shade_presentation(target_pptx_primary)
    try:
        build_shade_presentation(target_pptx_fallback)
    except Exception as e:
        print(f"Note: Could not overwrite SHADE_Presentation.pptx (likely open in PowerPoint). New file saved as: {target_pptx_primary}")
