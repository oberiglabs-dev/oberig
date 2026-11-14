# Benchmark fixtures

Ordinary content with no injections, cached so `node bench/run.js` runs offline and gives the same counts every time.

- `negatives.json.gz`: the tuning set (502 documents), used while improving the shield.
- `negatives-heldout.json.gz`: the held-out set (222 documents: other repositories, pages and templates), fetched after the rules were frozen.

Each file is gzipped JSON: `{ note, fetched, docs: [{ kind, id, source, license, text, ... }] }`. `kind` is `readme`, `issue-template`, `html-page` or `email`. Email templates have their `{{placeholders}}` filled with sample values, the way a delivered email reads, and the plain-text ones get a short header block (From, To, Subject, Date); everything else is stored as fetched.

The documents belong to their authors. They are kept here unchanged as test data under their own licenses, which each entry names next to its source URL. `node bench/fetch-negatives.js` (and `--heldout`) rebuilds the files; it needs the GitHub CLI and network access.
