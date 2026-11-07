# THREAT // ATLAS — Cloudflare Pages

A dark, responsive cyber threat-intelligence dashboard. It uses public defensive feeds and approximate IP geolocation. It does **not** depict confirmed real-time attacks or prove that an IP is currently attacking a particular country or target.

## Data sources

- Feodo Tracker recommended botnet C2 JSON blocklist: `https://feodotracker.abuse.ch/downloads/ipblocklist.json`
- SSLBL botnet C2 IP CSV: `https://sslbl.abuse.ch/blacklist/sslipblacklist.csv`
- Blocklist.de all-IP list: `https://lists.blocklist.de/lists/all.txt`
- IP geolocation: `https://ipwho.is/` (approximate location; up to 24 IP lookups per refresh)

The Feodo Tracker list can legitimately be empty following successful law-enforcement takedowns. The UI reports feed status and does not fabricate replacement events.

## Deploy to Cloudflare Pages

1. Create a Git repository and upload this folder's contents.
2. In Cloudflare Dashboard → Workers & Pages → Create → Pages → Connect to Git.
3. Select the repository. Framework preset: **None**. Build command: leave blank. Build output directory: `/` (or `.` if accepted by the dashboard).
4. Deploy. The `functions/api/threats.js` file creates the `/api/threats` endpoint automatically.
5. Open the `*.pages.dev` URL and check the feed status cards.

Alternative CLI deployment:

```bash
npm install -g wrangler
npx wrangler pages project create threat-atlas
npx wrangler pages deploy . --project-name threat-atlas
```

Pages Functions require a deployment path that processes the `functions/` directory. For local testing:

```bash
npx wrangler pages dev .
```

## Operational notes

- Feed fetches are cached at the Cloudflare edge for 5 minutes; the browser refreshes every 5 minutes.
- IP geolocation is deliberately capped at 24 addresses per refresh to reduce third-party API load. Additional IPs may appear in the feed without map coordinates.
- No API key is required for the three configured feed downloads. Provider availability, rate limits, and terms can change.
- Leaflet, OpenStreetMap/CARTO tiles, and Google Fonts are loaded from third-party CDNs.
- This is an intelligence visualization, not an incident-response or blocking tool. Validate indicators with the source before acting.
