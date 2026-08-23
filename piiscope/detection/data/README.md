# Built-in Dictionaries

This directory contains the built-in dictionaries used by the detection engine. 

## given_names.txt
- **Source**: Wikidata SPARQL (items that are instances of male, female, or unisex given name with sitelinks >= 5) and curated top-100 lists for several locales.
- **License**: CC0 (Wikidata) / Public Domain (curated lists)
- **Regeneration**: `python scripts/build_dictionaries.py --out piiscope/detection/data --cache <cache_dir>`
- **Runtime Extension**: Users can extend this list at runtime by supplying `--dictionary given_name=path/to/custom_names.txt`.

## surnames.txt
- **Source**: US Census Bureau 2010 surnames file and curated top-100 lists for several locales.
- **License**: Public Domain
- **Regeneration**: `python scripts/build_dictionaries.py --out piiscope/detection/data --cache <cache_dir>`
- **Runtime Extension**: Users can extend this list at runtime by supplying `--dictionary surname=path/to/custom_surnames.txt`.

## drug_names.txt
- **Source**: FDA Drugs@FDA data file and a curated list of common drugs.
- **License**: Public Domain
- **Regeneration**: `python scripts/build_dictionaries.py --out piiscope/detection/data --cache <cache_dir>`
- **Runtime Extension**: Users can extend this list at runtime by supplying `--dictionary drug_name=path/to/custom_drugs.txt`.

## medical_terms.txt
- **Source**: Curated list of conditions, symptoms, and diagnoses with their German and Turkish equivalents.
- **License**: Public Domain
- **Regeneration**: `python scripts/build_dictionaries.py --out piiscope/detection/data --cache <cache_dir>`
- **Runtime Extension**: Users can extend this list at runtime by supplying `--dictionary medical_condition=path/to/custom_conditions.txt`.

## hospital_keywords.txt
- **Source**: Curated list of institution keywords across multiple languages.
- **License**: Public Domain
- **Regeneration**: `python scripts/build_dictionaries.py --out piiscope/detection/data --cache <cache_dir>`
- **Runtime Extension**: Users can extend this list at runtime by supplying `--dictionary hospital_keyword=path/to/custom_hospitals.txt`.
