"""Python string template loader for DPDP Act 2023 statutory notices."""

from pathlib import Path
from string import Template

TEMPLATE_FILE = Path(__file__).parent / "section_12_erasure.md"

def load_section_12_template() -> Template:
    """Loads the official Section 12 markdown template."""
    with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
        return Template(f.read())

SUBJECT_TEMPLATE = Template(
    "STATUTORY NOTICE UNDER SECTION 12 OF DPDP ACT, 2023: REQUISITION FOR ERASURE OF PERSONAL DATA - $identifier"
)
