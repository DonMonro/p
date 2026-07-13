# Adding / editing countries

The list of selectable Psiphon countries lives in [`../config/countries.yaml`](../config/countries.yaml).

Because Psiphon's upstream `EgressRegion` set drifts over time, this list is
**just a YAML file** — no code changes are needed to extend or trim it.

## Adding a country

```yaml
countries:
  - code: NZ            # ISO-3166 alpha-2, uppercase
    name: New Zealand
    flag: 🇳🇿           # emoji glyph; render in the wizard + inbound remark
    region: Oceania
```

The panel reloads the file on boot; the wizard re-reads it fresh through the
`GET /api/countries` endpoint (cached per-process; restart the panel service to
force a refresh if you edit while it's running).

## Removing a country

Delete its `- code: …` block. Existing cloned inbounds for that country are not
auto-removed — use the dashboard's "remove country" button, which removes both
the tunnel process and the corresponding 3x-ui inbound.

## Displaying the count

The UI should always show the **current** count from `GET /api/countries`
(`count` field), never a hard-coded "32".
