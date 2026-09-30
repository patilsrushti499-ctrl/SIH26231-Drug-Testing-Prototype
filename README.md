# Digital Companion for Field Drug Testing

Full-stack prototype: installable browser app plus a Python API, operator/supervisor accounts, SQLite record store, captured-image storage, and unsigned demo/training records with SHA-256 image and record hashes. Captures can be queued on-device while offline and synced when connectivity returns. After capture, the operator marks the reaction pad and a neutral card patch; the app records the selected areas and illustrative assessment. Any saved image is labelled **DEMO · TRAINING · NOT EVIDENCE**. The server verifies stored hashes but does not digitally sign demo records; field-evidence signing is disabled.

## Run locally

1. Install Python 3.10 or newer.
2. In this folder, install the dependency with `python -m pip install -r requirements.txt`.
3. Start the app with `python server.py`.
4. Open <http://127.0.0.1:4173>.

## Development QA supervisor account

On startup, the server creates `QA-SUP` with password `ABC@123456` if that ID does not already exist in the selected database. Existing accounts are not changed, and the password is stored as a salted hash. This fixed credential is for local development only; do not expose the server publicly or use this credential for real data.

## Quick demo

1. Sign in as a field officer (a supervisor can create officer accounts under **Manage officers**). Choose **Load simulated sample** or upload/capture an image, mark the reaction area and one neutral gray square from the 24-patch card, and show the demo/presumptive category and match-to-profile score. Save with **Save demo record · not evidence**. GPS is optional; a missing fix is explicitly recorded. Both hashes are checked and the unsigned record appears in history.
2. A photo assessment uses an image of an identified kit and reference card (or the camera). The operator marks the reaction and neutral gray patches. The output remains provisional and unvalidated; do not use an actual sample for a prototype demonstration.
3. Field-record signing is intentionally disabled. Demo records are unsigned and clearly labelled **DEMO · TRAINING · NOT EVIDENCE**. Do not present a local prototype hash check as scientific validation or chain of custody.
4. Choose **Hash check** in the log to compare the stored image against its SHA-256 digest, or **JSON** to download the unsigned record. Open the record ID to view the saved image; search by operator or kit to show retrieval.

The **Protocol** item opens a quick pre-capture checklist (a reminder, not a replacement for kit instructions). The test log can be narrowed by outcome, training vs field records, or pending offline sync; combine the filter with search to find records faster.

The selected gray square is used for per-channel white-balance correction only; the app does not build a full 24-patch camera profile. If testing indoors or in a browser without location permission, GPS may fail; allow location access or use the app outdoors. Do not present the simulated sample as a real drug test or as laboratory-confirmed evidence.

The first run creates `data/`, containing the SQLite database and uploaded images. Keep this folder with the project if you want to preserve records across restarts. Do not use this prototype for real evidence.

The test log opens each saved image from its record link. The demo hash-check endpoint is `/api/records/<record-id>/verify`; it reports the image hash separately and never claims a demo record is signed.

## Prototype limits

- The starter colour references are illustrative and cannot be signed. Configured references are recorded as operator-entered and unvalidated; validate a ruleset against one identified test kit before interpreting results. Settings entered in the app do not establish scientific validity. The displayed rule-fit score is a distance-to-reference score, not a statistical probability.
- A kit-specific, qualified validation study has not been supplied or performed. The server therefore rejects all `field-test` signatures, even if someone changes browser settings or manually calls the API. Re-enabling field signing requires an independently reviewed validation package for the exact test kit, reagent lot(s), device/camera workflow, lighting/card process, operating instructions, and acceptance criteria, plus server-verifiable approval. A color card alone does not validate the chemistry or result categories.
- Demo/training records are unsigned. A SHA-256 digest can detect whether stored image bytes changed, but it does not authenticate the operator, time, location, scientific outcome, or chain of custody.
- The app requires an operator identifier but allows a demo record to be saved without GPS; missing location is shown as missing. The identifier is entered by the user, and browser GPS can be spoofed; neither is authenticated evidence of identity or physical presence.
- The backend stores demo image and metadata and checks the image hash. It does not sign demo records or prove the test was performed correctly or that operator identity/location are genuine.
- Operator IDs are recorded as entered but are not authenticated. GPS is supplied by the device/browser and can be spoofed. This local prototype is not a custody or identity system.
- Demo records are available only on the computer running this server. New captures can be queued offline on the device and sync when it reconnects to that server.
- Offline captures are held in browser IndexedDB until they can sync; clearing browser data before sync will lose the pending copy.
- Installability, camera, GPS, and service workers require localhost for development or HTTPS when deployed.
- The app has supervisor and field-officer logins, but it is a prototype and has not had a security review. Do not put real case data, personal information, or operational credentials in it.
- Results are presumptive and do not replace laboratory confirmation.

## Optional web demo deployment (Render)

This deploys the demo publicly; anyone with its URL can reach the login page. Use synthetic data only. Never upload the local `data/` folders, SQLite databases, uploaded images, or private keys. They are excluded by `.gitignore`.

1. Push only the source files in this folder to a private GitHub repository.
2. In Render, create a **Web Service** from that repository. Set the root directory to `outputs` if this folder is inside a larger repository.
3. Set the build command to `pip install -r requirements.txt`.
4. Set the start command to `FIELDTEST_HOST=0.0.0.0 FIELDTEST_DATA_DIR=/var/data FIELDTEST_SECURE_COOKIES=true python server.py`.
5. Attach a persistent disk mounted at `/var/data`. The free web-service plan has no persistent disk and may discard uploaded records, images, and account data on restart or sleep. A persistent disk requires a paid service; confirm current pricing in Render before enabling billing.
6. Deploy. Open the generated HTTPS address and create the first supervisor account. Then use **Manage officers** to create a field-officer account.

The app reads Render's `PORT` variable automatically. Its SQLite database and images stay on the attached disk. This hosting setup is only for a controlled prototype demonstration, not operational evidence handling.
