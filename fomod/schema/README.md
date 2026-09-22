# Vendored FOMOD schema

`ModConfig5.0.xsd` is the upstream FOMOD module-config schema from
<http://qconsulting.ca/gemm/ModConfig5.0.xsd> (the generic schema; the
`qconsulting.ca/fo3/ModConfig5.0.xsd` URL only redefines it to add
`foseDependency`). It is vendored so CI can validate `fomod/ModuleConfig.xml`
against the spec without depending on that host being reachable.

Two deliberate local changes, both mechanical:

1. `type=" xs:string"` was fixed to `type="xs:string"` on the `versionDependency`
   attribute. The leading space is an upstream typo and makes libxml2 refuse to
   compile the schema at all.
2. CRLF line endings were normalised to LF.

Neither changes a rule. The schema is used only by `tools/validate_fomod.py`
(via `xmllint`) and is not part of the mod archive.