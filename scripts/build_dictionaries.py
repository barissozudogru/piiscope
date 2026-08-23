#!/usr/bin/env python3
"""Build dictionaries from real, redistributable sources."""

import argparse
import csv
import io
import json
import re
import time
import unicodedata
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

# Headers
HEADER_TEMPLATE = """# Source: {source}
# License: {license}
# Retrieval Date: 2026-08-23
# Record Count: {count}
# Rule: lowercase, one entry per line, ASCII-folded variants included
"""

MUST_HAVE_GIVEN = [
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
    "joão",
    "pedro",
    "lucas",
    "gabriel",
    "rafael",
    "ana",
    "júlia",
    "beatriz",
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
    "mohammed",
    "ahmed",
    "omar",
    "fatima",
    "aisha",
    "youssef",
]

MUST_HAVE_SURNAMES = [
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

EXISTING_MEDICAL_TERMS = [
    "acne",
    "adipositas",
    "akne",
    "alopecia",
    "alzheimer",
    "anemi",
    "anemia",
    "angst",
    "anksiyete",
    "anxiety",
    "anämie",
    "appendicitis",
    "aritmi",
    "arrhythmia",
    "arthritis",
    "artrit",
    "asthma",
    "astım",
    "autism",
    "autismus",
    "bipolar",
    "bluthochdruck",
    "bronchitis",
    "bronşit",
    "cancer",
    "cholera",
    "cirrhosis",
    "covid",
    "demans",
    "dementia",
    "demenz",
    "depression",
    "depresyon",
    "diabetes",
    "diyabet",
    "eczema",
    "egzama",
    "ekzem",
    "encephalitis",
    "endometriose",
    "endometriosis",
    "endometriyozis",
    "epilepsi",
    "epilepsie",
    "epilepsy",
    "fibromiyalji",
    "fibromyalgia",
    "fibromyalgie",
    "frengi",
    "glaucoma",
    "glaukom",
    "glokom",
    "gout",
    "grip",
    "grippe",
    "hamilelik",
    "heart attack",
    "heart failure",
    "hepatit",
    "hepatitis",
    "herzinfarkt",
    "herzinsuffizienz",
    "hipertansiyon",
    "hiv",
    "hypertension",
    "influenza",
    "inme",
    "insomnia",
    "jaundice",
    "kabakulak",
    "kalp krizi",
    "kalp yetmezliği",
    "kanser",
    "kolera",
    "krebs",
    "kızamık",
    "kızamıkçık",
    "lenfoma",
    "leukemia",
    "leukämie",
    "lungenentzündung",
    "lupus",
    "lymphom",
    "lymphoma",
    "lösemi",
    "malaria",
    "masern",
    "measles",
    "melanom",
    "melanoma",
    "meningitis",
    "migraine",
    "migren",
    "migräne",
    "mumps",
    "myocardial infarction",
    "obesity",
    "obezite",
    "otizm",
    "pancreatitis",
    "pneumonia",
    "pregnancy",
    "psoriasis",
    "rosacea",
    "rubella",
    "röteln",
    "schizophrenia",
    "schizophrenie",
    "schlaflosigkeit",
    "schlaganfall",
    "schwangerschaft",
    "sciatica",
    "sedef",
    "stroke",
    "syphilis",
    "sıtma",
    "tinnitus",
    "tuberculosis",
    "tuberkulose",
    "tüberküloz",
    "uykusuzluk",
    "vertigo",
    "vitiligo",
    "zatürre",
    "şizofreni",
]

HOSPITAL_KEYWORDS = [
    "hospital",
    "clinic",
    "medical center",
    "hastane",
    "klinik",
    "poliklinik",
    "krankenhaus",
    "klinikum",
    "hôpital",
    "clinique",
    "ospedale",
    "clinica",
    "ziekenhuis",
    "kliniek",
    "szpital",
    "klinika",
]


def fold_ascii(text):
    text = text.replace("ı", "i").replace("ß", "ss").replace("ø", "o").replace("æ", "ae")
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))


def emit_variants(entries):
    result = set()
    for entry in entries:
        entry = entry.strip().lower()
        if not entry or len(entry) < 3:
            continue
        result.add(entry)
        folded = fold_ascii(entry)
        if folded != entry and len(folded) >= 3:
            result.add(folded)
    return sorted(result)


WIKIDATA_ENDPOINT = "https://query.wikidata.org/sparql"
WIKIDATA_CLASSES = {
    "Q12308941": "male given name",
    "Q11879590": "female given name",
    "Q3409032": "unisex given name",
}
WIKIDATA_LANGUAGES = ("en", "de", "tr", "es", "pt", "fr", "it", "nl", "pl")
WIKIDATA_MIN_SITELINKS = 5
USER_AGENT = "piiscope-dictionary-builder/1.0 (https://github.com/barissozudogru/piiscope)"


def _sparql(query: str, timeout: int = 120, retries: int = 6) -> dict:
    """Run one SPARQL query against Wikidata with retries on throttling and timeouts."""
    url = WIKIDATA_ENDPOINT + "?query=" + urllib.parse.quote(query)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/sparql-results+json"},
    )
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in (429, 500, 502, 503, 504):
                raise
        except Exception as exc:  # network hiccups, truncated streams
            last_error = exc
        time.sleep(min(60, 5 * (2 ** attempt)))
    raise RuntimeError(f"Wikidata query failed after {retries} attempts: {last_error}")


def fetch_wikidata(cache_dir):
    """Collect given names from Wikidata (CC0).

    One query per name class, restricted to items with at least
    WIKIDATA_MIN_SITELINKS sitelinks (a popularity proxy), keeps each request a
    few seconds long and well under the endpoint's 60 second limit. Responses
    are cached so a rerun only fetches what is missing.
    """
    names: set[str] = set()
    label_re = re.compile(r"^[A-Za-z\s\-']+$")
    langs = ", ".join(f'"{lang}"' for lang in WIKIDATA_LANGUAGES)
    for class_id, class_name in WIKIDATA_CLASSES.items():
        cache_file = cache_dir / f"wikidata_{class_id}_sl{WIKIDATA_MIN_SITELINKS}.json"
        if cache_file.exists():
            labels = json.loads(cache_file.read_text(encoding="utf-8"))
        else:
            query = f"""
            SELECT DISTINCT (STR(?label) AS ?name) WHERE {{
              ?item wdt:P31 wd:{class_id} ;
                    wikibase:sitelinks ?sl .
              FILTER(?sl >= {WIKIDATA_MIN_SITELINKS})
              ?item rdfs:label ?label .
              FILTER(LANG(?label) IN ({langs}))
            }}
            LIMIT 100000
            """
            print(f"Wikidata: {class_name} ...", flush=True)
            data = _sparql(query)
            labels = [row["name"]["value"] for row in data["results"]["bindings"]]
            cache_file.write_text(json.dumps(labels, ensure_ascii=False), encoding="utf-8")
        for label in labels:
            label = label.strip()
            if not label or len(label) > 25 or any(ch.isdigit() or ch in "()" for ch in label):
                continue
            if label_re.match(fold_ascii(label)):
                names.add(label)
    print(f"Wikidata: {len(names)} distinct given names")
    return sorted(names)


def fetch_census(cache_dir):
    cache_file = cache_dir / "names.zip"
    if not cache_file.exists():
        print("Fetching Census surnames...")
        req = urllib.request.Request(
            "https://www2.census.gov/topics/genealogy/2010surnames/names.zip",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req) as response, open(cache_file, "wb") as out_file:
            out_file.write(response.read())

    surnames = []
    with zipfile.ZipFile(cache_file) as z:
        for info in z.infolist():
            if info.filename.endswith(".csv"):
                with z.open(info.filename) as f:
                    content = f.read().decode("utf-8-sig", errors="replace")
                    reader = csv.reader(io.StringIO(content))
                    next(reader)
                    for i, row in enumerate(reader):
                        if i >= 25000:
                            break
                        if row:
                            surnames.append(row[0])
                break
    return surnames


def fetch_fda(cache_dir):
    cache_file = cache_dir / "fda.zip"
    if not cache_file.exists():
        print("Fetching FDA drugs...")
        req = urllib.request.Request(
            "https://www.fda.gov/media/89850/download", headers={"User-Agent": "curl/8.4.0"}
        )
        with urllib.request.urlopen(req) as response, open(cache_file, "wb") as out_file:
            out_file.write(response.read())

    drugs = set()
    with zipfile.ZipFile(cache_file) as z:
        if "Products.txt" in z.namelist():
            with z.open("Products.txt") as f:
                content = f.read().decode("utf-8", errors="replace")
                reader = csv.DictReader(io.StringIO(content), delimiter="\t")
                for row in reader:
                    dn = row.get("DrugName", "")
                    ai = row.get("ActiveIngredient", "")
                    for val in [dn] + re.split(r"[;,]", ai):
                        val = re.sub(r"\(.*?\)", "", val).strip()
                        if len(val) >= 4 and not val.isdigit():
                            drugs.add(val)
    return list(drugs)


def _curated():
    """Per-locale top lists maintained in scripts/curated_names.py."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from curated_names import GIVEN_NAMES_BY_LOCALE, SURNAMES_BY_LOCALE
    given = [n for names in GIVEN_NAMES_BY_LOCALE.values() for n in names]
    surnames = [n for names in SURNAMES_BY_LOCALE.values() for n in names]
    return given, surnames


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--cache", required=True)
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = Path(args.cache)
    cache_dir.mkdir(parents=True, exist_ok=True)

    curated_given, curated_surnames = _curated()

    # Given Names
    wiki_names = fetch_wikidata(cache_dir)
    given = emit_variants(wiki_names + curated_given + MUST_HAVE_GIVEN)
    gn_path = out_dir / "given_names.txt"
    with open(gn_path, "w") as f:
        f.write(HEADER_TEMPLATE.format(
                source="Wikidata given-name items (CC0) plus curated per-locale top lists",
                license="CC0 / public statistics",
                count=len(given),
            ))
        f.write("\n".join(given) + "\n")

    # Surnames
    census_surnames = fetch_census(cache_dir)
    surnames = emit_variants(census_surnames + curated_surnames + MUST_HAVE_SURNAMES)
    sn_path = out_dir / "surnames.txt"
    with open(sn_path, "w") as f:
        f.write(
            HEADER_TEMPLATE.format(
                source="US Census Bureau 2010 surnames (top 25000) plus curated top lists",
                license="Public domain / public statistics",
                count=len(surnames),
            )
        )
        f.write("\n".join(surnames) + "\n")

    # Drugs
    fda_drugs = fetch_fda(cache_dir)
    drugs = emit_variants(fda_drugs + MUST_HAVE_DRUGS)
    drug_path = out_dir / "drug_names.txt"
    with open(drug_path, "w") as f:
        f.write(
            HEADER_TEMPLATE.format(
                source="FDA Drugs@FDA", license="Public Domain", count=len(drugs)
            )
        )
        f.write("\n".join(drugs) + "\n")

    # Medical Terms
    medical = emit_variants(MUST_HAVE_CONDITIONS + EXISTING_MEDICAL_TERMS)
    med_path = out_dir / "medical_terms.txt"
    with open(med_path, "w") as f:
        f.write(
            HEADER_TEMPLATE.format(source="Curated", license="Public Domain", count=len(medical))
        )
        f.write("\n".join(medical) + "\n")

    # Hospital Keywords
    hospitals = emit_variants(HOSPITAL_KEYWORDS)
    hosp_path = out_dir / "hospital_keywords.txt"
    with open(hosp_path, "w") as f:
        f.write(
            HEADER_TEMPLATE.format(source="Curated", license="Public Domain", count=len(hospitals))
        )
        f.write("\n".join(hospitals) + "\n")

    print("Dictionaries built successfully.")


if __name__ == "__main__":
    main()
