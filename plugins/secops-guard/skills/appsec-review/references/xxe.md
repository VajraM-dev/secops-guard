# XML External Entity (XXE) and Entity Expansion

**CWE:** CWE-611 (Improper Restriction of XML External Entity Reference), CWE-776 (XML Entity Expansion / billion laughs), CWE-827 (Improper Control of Document Type Definition)

An XML parser resolves a DTD supplied by the document, so attacker markup can read local files, reach internal hosts (SSRF), or exhaust memory and CPU through nested entity expansion.

## How it gets introduced

- Parsing untrusted XML with `lxml` defaults: `etree.parse`/`fromstring` still resolve entities and load a network DTD unless a hardened parser is passed.
- `xml.dom.minidom`, `xml.sax`, `xml.dom.pulldom` left on stdlib defaults, which still process DTDs and internal entity expansion.
- Node `libxmljs`/`libxmljs2` parsed with `{ noent: true }` or `{ replaceEntities: true }`, or `noblanks`-style option copy-paste that includes `dtdload`/`dtdattr`.
- Any format that is XML underneath: SVG uploads, DOCX/XLSX/PPTX (`.xml` parts inside the zip), SAML assertions, SOAP bodies, RSS/Atom feeds, XML sitemaps, SOAP-ish webhook callbacks.
- XInclude enabled (`etree.XInclude()`, `xinclude=True`) on a document the user controls — a second file-read primitive even with entities off.
- Entity expansion limits left to the parser (billion laughs / quadratic blowup) on a size-unbounded upload.
- Parsing the XML to "just check it" before rejecting it: the resolution happens during parse, so a later validation step is too late.

## Python / FastAPI / SQLAlchemy / Pydantic

Python 3.9+ `xml.etree.ElementTree` no longer expands external entities (it raises on an external reference), but `lxml` does resolve them by default, and entity-expansion DoS is still possible on several stdlib parsers. Do not treat "stdlib" as a blanket safe answer.

```python
# vulnerable
from lxml import etree

@app.post("/import")
async def import_feed(body: bytes = Body(...)):
    doc = etree.fromstring(body)           # default parser: resolve_entities=True, DTD load on
    return {"items": len(doc.findall("item"))}
```

```python
# fixed
from defusedxml.lxml import fromstring as defused_fromstring   # simplest: defusedxml wrapper
# or build the hardened parser explicitly:
from lxml import etree

SAFE = etree.XMLParser(
    resolve_entities=False,   # no entity substitution at all
    no_network=True,          # no network fetch for DTDs/schemas
    load_dtd=False,
    dtd_validation=False,
    huge_tree=False,          # keep libxml2's depth/size limits on
)

MAX_XML = 2 * 1024 * 1024

@app.post("/import")
async def import_feed(request: Request):
    body = await request.body()
    if len(body) > MAX_XML:                # bound the input before parsing
        raise HTTPException(413)
    try:
        doc = etree.fromstring(body, parser=SAFE)
    except etree.XMLSyntaxError:
        raise HTTPException(422, "invalid XML")
    # never call doc.xinclude() / etree.XInclude() on untrusted input
    return {"items": len(doc.findall("item"))}
```

Other entry points:

```python
# fixed
import defusedxml.ElementTree as DET        # drop-in for xml.etree
import defusedxml.minidom as DMD            # drop-in for xml.dom.minidom
DET.fromstring(data)                        # raises EntitiesForbidden / DTDForbidden

# Office documents: openpyxl/python-docx parse the inner XML with lxml.
# Treat an uploaded .docx/.xlsx as untrusted XML — scan or sandbox it, and cap size.

# SVG upload: strip it, do not parse-and-trust. SVG is both an XXE and an XSS vector.
import nh3
clean_svg = nh3.clean(svg_text, tags={"svg", "path", "g", "circle", "rect"}, attributes={"*": {"d", "fill", "viewBox"}})
# safer still: re-encode to PNG server-side and serve that, or serve the SVG from a
# separate origin with Content-Disposition: attachment and a restrictive CSP.
```

## JS / TS / Node / React

```ts
// vulnerable
import libxmljs from "libxmljs2";
const doc = libxmljs.parseXml(body, { noent: true, dtdload: true });  // entity substitution + DTD fetch
```

```ts
// fixed
import libxmljs from "libxmljs2";

const doc = libxmljs.parseXml(body, {
  noent: false,    // do not substitute entities
  dtdload: false,  // do not load an external DTD
  dtdvalid: false,
  nonet: true,     // no network access during parse
  noblanks: true,
});
if (doc.errors.length) throw new BadRequest("invalid XML");
```

```ts
// fixed — preferred: a parser with no DTD support at all
import { XMLParser } from "fast-xml-parser";

const parser = new XMLParser({ ignoreAttributes: false, processEntities: false });
const data = parser.parse(body);   // no external entities, no DTD resolution
```

`fast-xml-parser` and `@xmldom/xmldom` (current versions) do not resolve external entities; `fast-xml-parser` still expands *internal* entities unless `processEntities: false`, so set it on untrusted input. Cap the body (`express.text({ limit: "2mb" })`) before any parse. In the browser, `DOMParser` does not load external entities — but never feed its output into `innerHTML` unsanitized.

## The safe API, per framework

| Parser | Control |
|---|---|
| `lxml` | `XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False)` |
| `xml.etree` (3.9+) | external entities already refused; use `defusedxml.ElementTree` for DTD/expansion guards too |
| `xml.dom.minidom`, `xml.sax`, `pulldom` | `defusedxml.minidom` / `defusedxml.sax` drop-ins |
| `xmlrpc`, SOAP (`zeep`) | `defusedxml.xmlrpc.monkey_patch()`; zeep uses a hardened lxml parser — verify the version |
| SAML (`python3-saml`, `pysaml2`) | keep the library's own hardened parser; never pre-parse the assertion yourself |
| Office files | size cap + a hardened lxml parser; prefer extracting only the parts you need |
| `libxmljs2` | `{ noent: false, dtdload: false, nonet: true }` |
| `fast-xml-parser` | safe by default; add `processEntities: false` |
| `@xmldom/xmldom` | no external entity resolution; keep the version current |
| XInclude | never enable on untrusted documents |

## Grep for

```
rg -n 'etree\.(parse|fromstring|XML)\(' -g '*.py' | rg -v 'parser=|defusedxml'   # lxml parse with default (unsafe) parser
rg -n 'XMLParser\(' -A4 -g '*.py' | rg -v 'resolve_entities=False'               # parser built without the entity switch
rg -n 'resolve_entities\s*=\s*True|no_network\s*=\s*False|huge_tree\s*=\s*True'  # explicitly re-enabled danger
rg -n 'load_dtd\s*=\s*True|dtd_validation\s*=\s*True'                            # DTD processing on
rg -n 'xinclude|XInclude'                                                        # file read primitive even with entities off
rg -n 'import xml\.(etree|dom|sax)' -g '*.py' | rg -v defusedxml                 # stdlib parser — check which and what version
rg -n 'minidom\.parse|sax\.parse|pulldom\.parse'                                 # DTD-processing stdlib entry points
rg -n 'noent\s*:\s*true|replaceEntities\s*:\s*true|dtdload\s*:\s*true'           # libxmljs entity/DTD options on
rg -n 'parseXml\(|parseXmlString\(' -A3 | rg -v 'nonet'                          # libxmljs parse without nonet
rg -n 'processEntities' -g '*.ts' -g '*.js'                                      # fast-xml-parser: confirm it is false for untrusted input
rg -n 'image/svg\+xml|\.svg["\x27]' -g '!*test*'                                 # SVG accepted or served — XXE + XSS vector
```

## False positives

- `etree.fromstring(..., parser=SAFE)` where `SAFE` is the hardened parser — confirm the parser object, not just the call.
- `defusedxml.*` imports: the drop-ins raise `EntitiesForbidden`/`DTDForbidden` before any resolution.
- `xml.etree.ElementTree` on Python 3.9+ parsing untrusted data: external entities are already refused. It is still worth a size cap, but it is not CWE-611.
- XML built or parsed from a file shipped in the repo, a fixture, or a response from a service you control over TLS — no attacker-controlled bytes.
- `fast-xml-parser` and `@xmldom/xmldom` hits with no DTD options: safe by default on external entities.
- Browser `DOMParser` in client code — no external entity resolution in any current engine.

## Regression test

```python
# tests/test_xxe.py
import pytest

XXE = b"""<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r><item>&x;</item></r>"""

BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]>
<l>&d;</l>"""

SSRF_DTD = b"""<?xml version="1.0"?>
<!DOCTYPE r SYSTEM "http://127.0.0.1:1/evil.dtd"><r/>"""

@pytest.mark.anyio
@pytest.mark.parametrize("payload", [XXE, BILLION_LAUGHS, SSRF_DTD])
async def test_xml_import_refuses_dtd_payloads(client, payload):
    r = await client.post("/import", content=payload, headers={"content-type": "application/xml"})
    assert r.status_code == 422           # rejected at parse, not 200 and not a 500 traceback
    assert "root:" not in r.text          # no file content echoed back

@pytest.mark.anyio
async def test_oversized_body_rejected_before_parse(client):
    r = await client.post("/import", content=b"<r/>" + b" " * (3 * 1024 * 1024))
    assert r.status_code == 413
```

```ts
// import.xxe.test.ts (vitest)
const XXE = `<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`;

it("does not resolve an external entity", async () => {
  const res = await request(app).post("/import").type("application/xml").send(XXE);
  expect(res.status).toBe(400);
  expect(res.text).not.toContain("root:");
});
```
