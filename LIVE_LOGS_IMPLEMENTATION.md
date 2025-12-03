# Live Server Logs Implementation

## Overview
The Replay Attack Demo now displays real-time server audit logs, showing all replay attacks and messages being processed on the server. This provides complete transparency into the security mechanisms at work.

## What Was Implemented

### 1. **Frontend Enhancement (ReplayAttackDemo.jsx)**

#### State Management
```javascript
const [serverLogs, setServerLogs] = useState([]);
const [showLogs, setShowLogs] = useState(false);
const [logsLoading, setLogsLoading] = useState(false);
```

#### Data Fetching Function
```javascript
const fetchServerLogs = async () => {
  setLogsLoading(true);
  try {
    const response = await fetch('http://localhost:5000/api/logs', {
      headers: { 'Authorization': `Bearer ${mockUser.token}` }
    });
    if (response.ok) {
      const logs = await response.json();
      const replayLogs = logs.filter(log => 
        log.type === 'REPLAY_ATTACK_DETECTED' || 
        log.type === 'MESSAGE_SENT'
      ).slice(0, 20);
      setServerLogs(replayLogs);
    }
  } catch (err) {
    console.error('Failed to fetch logs:', err);
  } finally {
    setLogsLoading(false);
  }
};
```

#### Auto-Refresh Mechanism
```javascript
useEffect(() => {
  fetchServerLogs();
  const interval = setInterval(fetchServerLogs, 2000); // Refresh every 2 seconds
  return () => clearInterval(interval);
}, []);
```

### 2. **UI Layout - 2-Column Grid**

**Left Column (lg:col-span-2):**
- Attack buttons (4 scenarios)
- Clear results button
- Attack results with expandable details
- Shows legitimate messages vs attack attempts

**Right Column (lg:col-span-1):**
- Sticky server logs panel
- Shows all replay attacks and messages
- Real-time updates every 2 seconds

### 3. **Logs Panel Features**

**Header Controls:**
- Eye icon toggle to show/hide logs
- Refresh button with loading spinner
- Sticky positioning for easy viewing

**Log Entry Display:**
- Color-coded by type:
  - 🚨 Red for `REPLAY_ATTACK_DETECTED` (critical/warning)
  - ✅ Green for `MESSAGE_SENT` (info)
- Severity badge (CRITICAL, WARNING, INFO)
- Username of who triggered the event
- Precise timestamp (HH:MM:SS)
- IP address (if available)
- Event details/description

**Responsive Behavior:**
- Hides on mobile (only shows on lg screens and up)
- Max height 96 units with overflow scrolling
- Smooth transitions and hover effects

### 4. **Server-Side Integration**

The frontend connects to the existing `/api/logs` endpoint on the server:

**Endpoint:** `GET /api/logs`
- **Auth:** Required (JWT token in Authorization header)
- **Response:** Array of audit log entries
- **Fields Returned:**
  - `type`: Event type (e.g., 'REPLAY_ATTACK_DETECTED', 'MESSAGE_SENT')
  - `severity`: 'info', 'warning', or 'critical'
  - `username`: User who triggered the event
  - `timestamp`: ISO 8601 formatted date
  - `ipAddress`: Source IP address
  - `details`: Human-readable event description

### 5. **Filter Logic**

Frontend filters logs to show only:
1. **REPLAY_ATTACK_DETECTED** - When server blocks an attack
2. **MESSAGE_SENT** - When a legitimate message is accepted

Other log types are still collected on server but hidden from demo view.

## Attack Scenarios Demonstrated

### Attack 1: Duplicate Nonce Replay
- **What:** Attacker replays message with same nonce
- **Protection:** Nonce uniqueness check
- **Log Entry:** "Duplicate nonce detected from alice to bob"
- **Result:** 🚨 BLOCKED (CRITICAL)

### Attack 2: Sequence Number Abuse
- **What:** Attacker decrements sequence number
- **Protection:** Sequence monotonicity enforcement
- **Log Entry:** "Invalid sequence number from alice to bob"
- **Result:** 🚨 BLOCKED (CRITICAL)

### Attack 3: Timestamp Manipulation
- **What:** Attacker sets timestamp 6+ minutes in past
- **Protection:** 5-minute freshness window
- **Log Entry:** "Old timestamp from alice to bob"
- **Result:** 🚨 BLOCKED (WARNING)

### Attack 4: Sequence Collision
- **What:** Different nonce but same/lower sequence number
- **Protection:** Sequence counter enforcement
- **Log Entry:** "Invalid sequence number from alice to bob"
- **Result:** 🚨 BLOCKED (CRITICAL)

## User Interaction Flow

1. **User navigates to Replay Attack Demo**
   - ✅ Logs panel appears on right
   - ✅ Auto-refreshes every 2 seconds
   - ✅ Initially shows "No logs yet"

2. **User clicks an attack button** (e.g., "Attack 1: Duplicate Nonce Replay")
   - ✅ Attack is executed against server
   - ✅ Server detects and logs the attack
   - ✅ Within 2 seconds, new log appears in right panel
   - ✅ Log shows red background with 🚨 icon
   - ✅ Left panel shows attack blocked with details

3. **User can toggle logs visibility**
   - ✅ Click eye icon to hide/show logs panel
   - ✅ Logs continue fetching in background
   - ✅ Click refresh to manually update logs

4. **User clicks "Clear Results"**
   - ✅ Clears left panel attack results
   - ✅ Logs panel continues showing all events
   - ✅ New attacks will appear in both panels

## Technical Architecture

```
┌─────────────────────────────────────────────────┐
│           ReplayAttackDemo Component             │
├─────────────────────────────────────────────────┤
│                                                  │
│  ┌─────────────────┬──────────────────────────┐ │
│  │  Left Column    │   Right Column (Logs)    │ │
│  │  (lg:col-span-2)│   (lg:col-span-1)        │ │
│  │                 │                          │ │
│  │  ┌─────────────┐│┌──────────────────────┐ │ │
│  │  │Attack Button││ Toggle visibility     │ │ │
│  │  │ 1: Duplicate││ Refresh button        │ │ │
│  │  │ 2: Sequence ││                       │ │ │
│  │  │ 3: Timestamp││ ┌──────────────────┐ │ │ │
│  │  │ 4: Collision││ │ 🚨 REPLAY_ATTACK │ │ │ │
│  │  └─────────────┘│ │ alice → bob      │ │ │ │
│  │                 │ │ 14:32:15         │ │ │ │
│  │  Results        │ │ CRITICAL         │ │ │ │
│  │  ┌─────────────┐│ └──────────────────┘ │ │ │
│  │  │ Attack 1    ││ ┌──────────────────┐ │ │ │
│  │  │ BLOCKED ✅  │ │ ✅ MESSAGE_SENT   │ │ │ │
│  │  │ Details...  │ │ bob → alice      │ │ │ │
│  │  └─────────────┘│ │ 14:32:10         │ │ │ │
│  │                 │ │ INFO             │ │ │ │
│  │                 │ └──────────────────┘ │ │ │
│  │                 │                      │ │ │
│  └─────────────────┴──────────────────────┘ │ │
│                                              │ │
└──────────────────────────────────────────────┘ │
                      │                          │
                      ▼                          │
         ┌────────────────────────┐             │
         │  fetch() every 2sec     │             │
         └────────────────────────┘             │
                      │                          │
                      ▼                          │
         ┌────────────────────────┐             │
         │ GET /api/logs          │             │
         │ Authorization: Bearer  │             │
         │ token                  │             │
         └────────────────────────┘             │
                      │                          │
                      ▼                          │
         ┌────────────────────────┐             │
         │  Server (routes.js)    │             │
         │  Verify JWT token      │             │
         │  Query AuditLog DB     │             │
         │  Return last 50 logs   │             │
         │  (desc by timestamp)   │             │
         └────────────────────────┘             │
```

## Verification Checklist

- ✅ Logs fetch from `/api/logs` endpoint
- ✅ Logs auto-refresh every 2 seconds
- ✅ JWT authentication included in requests
- ✅ Logs filtered for REPLAY_ATTACK_DETECTED and MESSAGE_SENT
- ✅ Color-coded by type (red for attacks, green for messages)
- ✅ Severity badges displayed (CRITICAL, WARNING, INFO)
- ✅ Username displayed for each log
- ✅ Timestamp formatted as HH:MM:SS
- ✅ Eye icon toggle for show/hide
- ✅ Refresh button with loading state
- ✅ Sticky positioning on right column
- ✅ 2-column responsive layout
- ✅ No errors in component (syntax validation passed)

## Usage Instructions

1. **Start the application:**
   ```bash
   npm run dev  # client
   npm start    # server (in separate terminal)
   ```

2. **Navigate to Replay Attack Demo tab**

3. **Observe the logs panel on the right:**
   - Initially empty with "No logs yet" message
   - Toggle with eye icon to show/hide
   - Click refresh button to manually fetch latest logs

4. **Run an attack:**
   - Click any attack button
   - Within 2 seconds, the attack will appear in logs panel
   - Attack result shows on left with details
   - Log entry shows on right with color-coding

5. **Review attack details:**
   - Click on log entry to expand (if desired)
   - Compare attack attempt with legitimate message
   - See server's rejection reason

## Benefits

1. **Complete Transparency:** See exactly what the server is doing
2. **Real-Time Feedback:** Logs update automatically without refresh
3. **Security Verification:** Confirms all attacks are detected and logged
4. **Educational Value:** Shows how each protection layer works
5. **Audit Trail:** Historical record of all security events
6. **No Bypass:** Demonstrates server-side enforcement

## Future Enhancements

- [ ] Expandable log entries with full details
- [ ] Filter by event type (show only attacks, only messages, etc.)
- [ ] Search/filter logs by username
- [ ] Export logs to CSV/JSON
- [ ] Log aggregation statistics (attacks/min, etc.)
- [ ] Real-time notifications for critical events
- [ ] Log persistence across page reloads
