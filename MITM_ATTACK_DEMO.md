# MITM Attack Demonstration

This walkthrough explains how to capture the evidence required for Requirement 7.

## Overview
- **Attacker script:** implemented in `client/src/components/MitmAttackDemo.jsx`
- **Access:** open the dashboard and click `MITM Demo`
- The modal contains two simulations:
  1. **Insecure DH (no signatures)** — Mallory successfully decrypts and replays the traffic.
  2. **Signed ECDH (InfoSecProject protocol)** — signature verification fails when Mallory tampers, so the session aborts.

## How to Run & Collect Evidence
1. Start both backend (`npm start` in `server/`) and frontend (`npm run dev` in `client/`).
2. Log in as any user, select another registered user in the “Registered Users” list (this user represents the attacker), then click the blue **MITM Demo** button in the header.
3. Click **Run MITM Attack**.  
   - The left log panel will show Mallory deriving both shared secrets, decrypting “Attack at dawn,” and forwarding it.  
   - Take a screenshot of this panel plus the button state as proof of the successful attack.
4. Click **Run Defense Simulation**.  
   - The right log panel will show signature verification failing for the tampered handshake and succeeding for the untouched one. It also triggers a `MITM_ATTACK_DETECTED` security log tied to the logged-in user and the attacker’s username.  
   - Screenshot this panel as proof that the signed protocol blocks MITM, and capture the new log entry if desired.
5. Include both screenshots and (optionally) copy-paste the log text into your report.

## Optional BurpSuite / Proxy Trace
For an additional artefact, open the developer tools network tab or BurpSuite while running the demo and capture the console logs produced by the component. These logs explicitly state when Mallory reads the plaintext and when Bob aborts due to signature failure.

## Files Touched
- `client/src/components/MitmAttackDemo.jsx` — Attacker & defense simulations with detailed logs.
- `client/src/components/Dashboard.jsx` — Adds the **MITM Demo** entry point.
- `client/src/App.jsx` — Wires the modal into application routing.

Use this document as the narrative reference when writing the final report section on MITM testing.***

