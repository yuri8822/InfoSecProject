# Quick Verification Guide - Testing Live Logs in Action

## Prerequisites

1. **Server running** (port 5000)
   ```bash
   cd server
   npm install
   npm start
   ```

2. **Client running** (port 5173)
   ```bash
   cd client
   npm install
   npm run dev
   ```

3. **MongoDB connected**
   - Check server console: `Connected to MongoDB`
   - Ensure `.env` has valid `MONGODB_URI`

## Quick Verification Steps

### Step 1: Launch the Demo

1. Open browser: `http://localhost:5173`
2. Navigate to: **Replay Attack Protection Demo** tab
3. Verify you see:
   - ✅ Left panel with 4 attack buttons
   - ✅ Right panel with "Server Logs" header
   - ✅ Eye icon and refresh button in logs header
   - ✅ "No logs yet" message in logs area

### Step 2: View Initial Logs

1. Look at the **Server Logs** panel (right side)
2. Click eye icon to ensure panel is visible (🔍 should show)
3. Initially should show: "No logs yet. Run an attack to see logs."
4. Click refresh button (🔄)
5. Should see some initial logs (authentication, key fetches, etc.)
   - These are normal system logs

### Step 3: Execute First Attack

1. Click: **"Attack 1: Duplicate Nonce Replay"** button
   - Left panel shows attack executing
   - "Loading..." state appears

2. Within 1-2 seconds:
   - ✅ Result appears on left: "BLOCKED"
   - ✅ Attack details show below (expandable)
   - ✅ Shows legitimate vs attack attempt JSON

3. Within 2-3 seconds (next auto-refresh):
   - ✅ Red log entry appears in right panel
   - ✅ Log shows: "🚨 REPLAY_ATTACK_DETECTED"
   - ✅ Username: "alice"
   - ✅ Severity badge: "CRITICAL" (red)
   - ✅ Details: "Duplicate nonce detected from alice to bob"

### Step 4: Execute Remaining Attacks

Repeat Step 3 for each remaining attack:

2. **"Attack 2: Sequence Number Abuse"**
   - Expected in logs: "Invalid sequence number"
   - Severity: CRITICAL

3. **"Attack 3: Timestamp Manipulation"**
   - Expected in logs: "Old timestamp"
   - Severity: WARNING

4. **"Attack 4: Sequence Collision"**
   - Expected in logs: "Invalid sequence number"
   - Severity: CRITICAL

### Step 5: Verify Auto-Refresh

1. Keep running attacks every 5 seconds
2. Watch right panel logs area
3. Every 2 seconds, panel should auto-update with new logs
4. New attacks appear near bottom of list
5. Oldest logs scroll out (keeping last 20)

### Step 6: Test Toggle Visibility

1. Click eye icon in logs header
2. Logs content should disappear
3. Header remains visible (background color change)
4. Click refresh button - nothing visible (but fetching in background)
5. Click eye icon again
6. Logs reappear with latest entries

### Step 7: Clear Results

1. Click **"Clear Results"** button
2. Left panel attack results cleared
3. Right panel logs continue refreshing
4. Execute new attack
5. New result appears on left
6. Corresponding log appears on right

## Expected Observations

### Successful Verification Looks Like:

```
┌─────────────────────────────────┬──────────────────────┐
│ Left: Attack Results            │ Right: Server Logs   │
├─────────────────────────────────┼──────────────────────┤
│                                 │                      │
│ ┌─ Attack 1: ✅ BLOCKED ──┐    │ 🚨 REPLAY_ATTACK    │
│ │ Duplicate Nonce         │    │ DETECTED            │
│ │ Details...              │    │ CRITICAL            │
│ └─────────────────────────┘    │ alice, 14:32:15     │
│                                 │                      │
│ [Clear Results] [Refresh]      │ 🚨 REPLAY_ATTACK    │
│                                 │ DETECTED            │
│ ┌─ Attack 2: ✅ BLOCKED ──┐    │ CRITICAL            │
│ │ Sequence Abuse          │    │ alice, 14:32:12     │
│ │ Details...              │    │                      │
│ └─────────────────────────┘    │ ✅ MESSAGE_SENT     │
│                                 │ INFO                │
│ [+2 more results below]        │ alice, 14:32:05     │
│                                 │                      │
│                                 │ 🚨 REPLAY_ATTACK    │
│                                 │ DETECTED            │
│                                 │ WARNING             │
│                                 │ alice, 14:31:50     │
└─────────────────────────────────┴──────────────────────┘
```

### Success Indicators:
- ✅ All 4 attacks show "BLOCKED" result
- ✅ All attacks appear in server logs within 2-3 seconds
- ✅ Logs auto-update every 2 seconds
- ✅ Color coding correct (red for attacks, green for messages)
- ✅ Severity badges display correctly
- ✅ Usernames match (alice for attacker)
- ✅ Timestamps show recent times
- ✅ Toggle and refresh buttons work

## Troubleshooting

### Problem: Logs Panel Empty / "No logs yet" Stays

**Possible Causes:**
1. Server not connected to MongoDB
2. JWT token not recognized
3. Network error fetching logs

**Solutions:**
- Check server console for MongoDB connection error
- Verify `Authorization` header being sent (open DevTools → Network)
- Check browser console for fetch errors
- Click refresh button manually
- Ensure server is running on port 5000

### Problem: Attack Executes But No Log Appears

**Possible Causes:**
1. Auto-refresh hasn't triggered yet (every 2 seconds)
2. Log filter removing the entry
3. Database write failed

**Solutions:**
- Click refresh button manually
- Wait up to 3 seconds
- Check server console for any error messages
- Check MongoDB logs collection: `db.auditlogs.find()`

### Problem: Same Log Entry Appears Multiple Times

**Possible Causes:**
1. Multiple identical attacks executed
2. Auto-refresh showing same old entries

**Solutions:**
- This is actually correct behavior
- Each attack creates a new log entry
- Click "Clear Results" if needed
- Logs panel shows up to 20 most recent

### Problem: Wrong Severity Color

**Expected Mappings:**
- CRITICAL → Red badge (bg-red-600)
- WARNING → Yellow badge (bg-yellow-600)
- INFO → Green badge (bg-green-600)

**If Wrong:**
- Check server logs being created with correct severity
- Verify field name is `severity` not `level`
- Check CSS class application

### Problem: Layout Issues (Logs Panel Cut Off)

**On Desktop (lg screens up):**
- Should be 33% width on right
- Should be sticky (stays visible while scrolling)
- Left side is 66% width

**On Mobile:**
- Logs should be below attack results (single column)
- Full width

**Solutions:**
- Refresh browser
- Check window width (F12 → toggle device mode)
- Verify no custom CSS overriding Tailwind

## Performance Check

### Expected Performance:
1. **Attack Execution:** < 500ms (includes network roundtrip)
2. **Log Appearance:** 2-3 seconds (first auto-refresh cycle)
3. **UI Responsiveness:** Immediate (all buttons click instantly)
4. **Auto-Refresh:** Every 2 seconds consistently

### Check Performance:
1. Open DevTools → Performance tab
2. Click attack button
3. Record until log appears
4. Check Total Time < 5 seconds
5. Look for any red warning flags

### Network Check:
1. Open DevTools → Network tab
2. Filter by "api/logs" or "XHR"
3. Each request should show:
   - Request: GET /api/logs
   - Status: 200 (success)
   - Size: 2-5 KB
   - Time: < 100ms

## Database Verification

### Check Message Collection:

```bash
# Connect to MongoDB
mongo mongodb://localhost:27017/infosec

# View messages with replay protection fields
db.messages.find().limit(5).pretty()

# Expected output includes:
# {
#   from: "alice",
#   to: "bob",
#   nonce: "4a7d9f2e1b3c5a8d...",
#   sequenceNumber: 5,
#   timestamp: ISODate("2024-01-15T14:32:14Z"),
#   ...other fields...
# }
```

### Check Audit Log Collection:

```bash
# View latest attack logs
db.auditlogs.find({ type: "REPLAY_ATTACK_DETECTED" }).sort({ timestamp: -1 }).limit(5).pretty()

# Expected output:
# {
#   type: "REPLAY_ATTACK_DETECTED",
#   username: "alice",
#   severity: "critical",
#   details: "Duplicate nonce detected from alice to bob",
#   timestamp: ISODate("2024-01-15T14:32:15Z"),
#   ...other fields...
# }
```

## Code Verification Points

### Frontend Component Check:

**File:** `client/src/components/ReplayAttackDemo.jsx`

Check these exist:
- [ ] `fetchServerLogs()` function (lines ~32-47)
- [ ] `useEffect` hook for auto-refresh (lines ~49-53)
- [ ] State: `serverLogs`, `showLogs`, `logsLoading` (lines ~26-28)
- [ ] Grid layout with 2 columns (lines ~371)
- [ ] Eye icon toggle button (lines ~520)
- [ ] Logs map() function rendering entries (lines ~544-570)

### Backend Routes Check:

**File:** `server/routes.js`

Check these exist:
- [ ] GET `/logs` endpoint (line ~119)
- [ ] JWT verification in /logs route
- [ ] AuditLog queries returning last 50 logs
- [ ] POST `/messages` with 4-layer verification (lines ~184-230)
- [ ] createLog calls for REPLAY_ATTACK_DETECTED (lines ~201, 208, 215)

### Database Schema Check:

**File:** `server/server.js`

Check Message schema has:
- [ ] `nonce: { type: String, required: true }`
- [ ] `sequenceNumber: { type: Number, required: true }`
- [ ] `timestamp: { type: Date, default: Date.now }`

## Full Integration Test

### Complete Test Flow (5 minutes):

1. **Setup (30s)**
   - [ ] Server running
   - [ ] Client running
   - [ ] MongoDB connected
   - [ ] Browser at http://localhost:5173

2. **Initial State (30s)**
   - [ ] Demo loads
   - [ ] Logs panel visible
   - [ ] Shows "No logs yet"

3. **Execute Attacks (2m)**
   - [ ] Attack 1: ✅ Blocked, 🚨 Log appears
   - [ ] Attack 2: ✅ Blocked, 🚨 Log appears
   - [ ] Attack 3: ✅ Blocked, 🚨 Log appears
   - [ ] Attack 4: ✅ Blocked, 🚨 Log appears

4. **Verify Controls (1m)**
   - [ ] Eye icon toggles logs visibility
   - [ ] Refresh button fetches latest logs
   - [ ] Clear button removes results
   - [ ] New attacks show immediately

5. **Monitor Performance (1m)**
   - [ ] No console errors
   - [ ] Network requests successful
   - [ ] UI responsive
   - [ ] Logs update consistently

## Success Criteria

**All of the following must be TRUE:**

- ✅ When attack executed → ✅ result shows on left within 1 second
- ✅ When attack executed → 🚨 log appears on right within 2-3 seconds
- ✅ All 4 attacks return HTTP 400 (not HTTP 201)
- ✅ All 4 attacks logged with REPLAY_ATTACK_DETECTED
- ✅ Legitimate messages show in logs as MESSAGE_SENT
- ✅ Severity badges color-coded (red/yellow/green)
- ✅ Logs auto-refresh every 2 seconds
- ✅ No JavaScript errors in console
- ✅ No network errors in DevTools
- ✅ Layout responsive (2 columns on desktop, 1 on mobile)

## Verification Complete!

When all criteria above are met:

✅ **Live Logs Implementation is Fully Functional**

The Replay Attack Demo now provides:
- Real-time display of server audit logs
- Complete transparency into attack detection
- Educational demonstration of all 4 protection layers
- Production-ready monitoring interface
