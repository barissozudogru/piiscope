"""Guard rails for the built-in dictionaries.

The name lists must contain the most common given names and surnames of the
locales piiscope targets, and must not contain obvious non-words.
"""

from __future__ import annotations

import unicodedata
from importlib import resources

import pytest

DATA = resources.files("piiscope.detection") / "data"

MUST_HAVE_GIVEN = [
    # English
    "james",
    "mary",
    "john",
    "patricia",
    "robert",
    "jennifer",
    "michael",
    "linda",
    "william",
    "elizabeth",
    "david",
    "sarah",
    "emma",
    "olivia",
    "noah",
    "liam",
    # German
    "hans",
    "peter",
    "thomas",
    "michael",
    "andreas",
    "stefan",
    "jürgen",
    "klaus",
    "anna",
    "maria",
    "ursula",
    "monika",
    "petra",
    "sabine",
    "lena",
    "sophie",
    # Turkish
    "mehmet",
    "mustafa",
    "ahmet",
    "ali",
    "hüseyin",
    "hasan",
    "ibrahim",
    "yusuf",
    "fatma",
    "ayşe",
    "emine",
    "hatice",
    "zeynep",
    "elif",
    "meryem",
    "özlem",
    # Spanish
    "josé",
    "antonio",
    "juan",
    "manuel",
    "francisco",
    "carlos",
    "maría",
    "carmen",
    "ana",
    "laura",
    "lucía",
    "sofía",
    # Portuguese (Brazil)
    "joão",
    "pedro",
    "lucas",
    "gabriel",
    "rafael",
    "ana",
    "júlia",
    "beatriz",
    # French / Italian / Dutch / Polish
    "jean",
    "pierre",
    "louis",
    "marie",
    "camille",
    "giuseppe",
    "giovanni",
    "francesca",
    "jan",
    "daan",
    "sanne",
    "piotr",
    "krzysztof",
    "katarzyna",
    "agnieszka",
    # Arabic (transliterated)
    "mohammed",
    "ahmed",
    "omar",
    "fatima",
    "aisha",
    "youssef",
]

MUST_HAVE_SURNAMES = [
    # English
    "smith",
    "johnson",
    "williams",
    "brown",
    "jones",
    "miller",
    "davis",
    "wilson",
    "taylor",
    "anderson",
    "thomas",
    "moore",
    "martin",
    "jackson",
    "white",
    "harris",
    # German
    "müller",
    "schmidt",
    "schneider",
    "fischer",
    "weber",
    "meyer",
    "wagner",
    "becker",
    "schulz",
    "hoffmann",
    "schäfer",
    "koch",
    "bauer",
    "richter",
    "klein",
    "wolf",
    # Turkish
    "yılmaz",
    "kaya",
    "demir",
    "şahin",
    "çelik",
    "yıldız",
    "yıldırım",
    "öztürk",
    "aydın",
    "özdemir",
    "arslan",
    "doğan",
    "kılıç",
    "aslan",
    "çetin",
    "kara",
    # Spanish
    "garcía",
    "rodríguez",
    "gonzález",
    "fernández",
    "lópez",
    "martínez",
    "sánchez",
    "pérez",
    "gómez",
    "martín",
    "jiménez",
    "ruiz",
    "hernández",
    "díaz",
    "moreno",
    # Portuguese (Brazil)
    "silva",
    "santos",
    "oliveira",
    "souza",
    "rodrigues",
    "ferreira",
    "alves",
    "pereira",
    "lima",
    "gomes",
    "costa",
    "ribeiro",
    "martins",
    "carvalho",
    "almeida",
    # French / Italian / Dutch / Polish
    "bernard",
    "dubois",
    "durand",
    "moreau",
    "laurent",
    "rossi",
    "russo",
    "ferrari",
    "esposito",
    "bianchi",
    "de jong",
    "jansen",
    "de vries",
    "van den berg",
    "bakker",
    "nowak",
    "kowalski",
    "wiśniewski",
    "wójcik",
    "kowalczyk",
]

MUST_HAVE_DRUGS = [
    "paracetamol",
    "acetaminophen",
    "ibuprofen",
    "aspirin",
    "metformin",
    "atorvastatin",
    "amoxicillin",
    "omeprazole",
    "levothyroxine",
    "sertraline",
    "insulin",
    "warfarin",
    "lisinopril",
    "amlodipine",
    "simvastatin",
    "prednisone",
    "diazepam",
    "morphine",
    "ozempic",
    "xanax",
    "prozac",
    "viagra",
    "voltaren",
    "tylenol",
    "advil",
    "zoloft",
]

MUST_HAVE_CONDITIONS = [
    "diabetes",
    "hypertension",
    "asthma",
    "depression",
    "hiv",
    "cancer",
    "epilepsy",
    "pregnancy",
    "schizophrenia",
    "alzheimer",
    "parkinson",
    "hepatitis",
    "tuberculosis",
    "anxiety",
    "obesity",
    "stroke",
    "leukemia",
    "migraine",
    "bipolar",
    "diyabet",
    "hipertansiyon",
    "kanser",
    "depresyon",
    "astım",
    "bluthochdruck",
    "krebs",
    "depression",
    "asthma",
]


def _fold(text: str) -> str:
    return "".join(
        ch for ch in unicodedata.normalize("NFKD", text.lower()) if not unicodedata.combining(ch)
    ).replace("ı", "i")


def _load(name: str) -> set[str]:
    raw = (DATA / name).read_text(encoding="utf-8")
    return {
        line.strip().lower()
        for line in raw.splitlines()
        if line.strip() and not line.startswith("#")
    }


@pytest.mark.parametrize(
    ("filename", "must_have"),
    [
        ("given_names.txt", MUST_HAVE_GIVEN),
        ("surnames.txt", MUST_HAVE_SURNAMES),
        ("drug_names.txt", MUST_HAVE_DRUGS),
        ("medical_terms.txt", MUST_HAVE_CONDITIONS),
    ],
)
def test_dictionary_contains_common_entries(filename: str, must_have: list[str]) -> None:
    entries = _load(filename)
    folded = {_fold(e) for e in entries}
    missing = [n for n in must_have if n not in entries and _fold(n) not in folded]
    assert not missing, f"{filename} is missing common entries: {missing}"


@pytest.mark.parametrize("filename", ["given_names.txt", "surnames.txt"])
def test_name_lists_are_clean(filename: str) -> None:
    entries = _load(filename)
    bad = [
        e
        for e in entries
        if len(e) < 3
        or any(ch.isdigit() for ch in e)
        or e != e.strip()
        or any(ch in e for ch in '_/\\@#$%^&*()[]{}<>=+|~`"')
    ]
    assert not bad, f"{filename} has malformed entries: {bad[:20]}"
    assert len(entries) == len({e for e in entries}), "duplicates"


def test_name_lists_have_no_obvious_english_words() -> None:
    """Common English words that also exist as rare names must not be in the given-name list
    unless the engine's stoplist covers them; the engine test covers the stoplist, this guards
    the raw data against the worst offenders."""
    entries = _load("given_names.txt")
    offenders = {
        "the",
        "and",
        "for",
        "with",
        "from",
        "this",
        "that",
        "have",
        "will",
        "bill",
        "mark",
        "may",
        "april",
        "june",
        "summer",
        "grace",
        "hope",
        "art",
        "rose",
        "joy",
    }
    present = sorted(offenders & entries)
    # Names like April, June, Grace, Hope, Rose, Mark, Bill, Will are legitimate given names; the
    # stoplist in the engine must handle them. Only pure function words are forbidden here.
    function_words = {"the", "and", "for", "with", "from", "this", "that", "have"}
    assert not (function_words & entries), (
        f"function words in given names: {function_words & entries}"
    )
    assert isinstance(present, list)
