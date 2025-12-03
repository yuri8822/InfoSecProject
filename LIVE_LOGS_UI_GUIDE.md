# Replay Attack Demo - Live Logs UI Guide

## Visual Layout

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ InfoSec Project - Dashboard                                                  │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│                    🚨 Replay Attack Protection Demo                          │
│   Demonstrates how the system prevents replay attacks using nonces,          │
│   sequence numbers, and timestamps                                           │
│                                                                               │
├─────────────────────────────────────────────────────────┬─────────────────────┤
│                                                         │                     │
│  LEFT COLUMN (lg:col-span-2)                          │ RIGHT COLUMN        │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │ (lg:col-span-1)     │
│                                                         │ ━━━━━━━━━━━━━━━━━  │
│  ┌─ ATTACK BUTTONS ───────────────────────────────┐   │                     │
│  │ 🔴 Attack 1: Duplicate Nonce Replay             │   │ 👁️  Server Logs 🔄  │
│  │ 🔴 Attack 2: Sequence Number Abuse             │   │ ━━━━━━━━━━━━━━━━━━━ │
│  │ 🔴 Attack 3: Timestamp Manipulation            │   │                     │
│  │ 🔴 Attack 4: Sequence Collision                │   │ 🚨 REPLAY_ATTACK    │
│  │ [Clear Results] [Refresh]                      │   │ DETECTED            │
│  └────────────────────────────────────────────────┘   │ ━━━━━━━━━━━━━━━━━━━ │
│                                                         │ alice → bob         │
│  ┌─ ATTACK RESULTS ───────────────────────────────┐   │ 14:32:15            │
│  │ ┌── Attack 1: Duplicate Nonce Replay ──────┐ │   │ CRITICAL            │
│  │ │ ✅ BLOCKED (green badge)                  │ │   │                     │
│  │ │                                            │ │   │ ✅ MESSAGE_SENT     │
│  │ │ [EXPANDABLE - Click to show details]      │ │   │ ━━━━━━━━━━━━━━━━━━━ │
│  │ │                                            │ │   │ bob → alice         │
│  │ │ Protection Mechanism:                     │ │   │ 14:32:10            │
│  │ │ Nonce uniqueness check - each message     │ │   │ INFO                │
│  │ │ requires a unique random nonce            │ │   │                     │
│  │ │                                            │ │   │ 🚨 REPLAY_ATTACK    │
│  │ │ Legitimate Message:                       │ │   │ DETECTED            │
│  │ │ {                                          │ │   │ ━━━━━━━━━━━━━━━━━━━ │
│  │ │   "nonce": "4a7d9f2e...",                 │ │   │ alice → bob         │
│  │ │   "sequenceNumber": 5,                    │ │   │ 14:31:45            │
│  │ │   "timestamp": "2024-01-15T14:32:14Z"    │ │   │ WARNING             │
│  │ │ }                                          │ │   │                     │
│  │ │                                            │ │   │ [Auto-scroll area]  │
│  │ │ Attack Attempt:                           │ │   │ [Max 20 log entries]│
│  │ │ {                                          │ │   │ [Refresh every 2s]  │
│  │ │   "nonce": "4a7d9f2e...",  // SAME!      │ │   │                     │
│  │ │   "sequenceNumber": 6,                    │ │   │                     │
│  │ │   "timestamp": "2024-01-15T14:32:14Z"    │ │   │                     │
│  │ │ }                                          │ │   │                     │
│  │ │                                            │ │   │                     │
│  │ │ Server Response:                          │ │   │                     │
│  │ │ HTTP 400 - Replay attack detected         │ │   │                     │
│  │ └────────────────────────────────────────┘ │ │   │                     │
│  │                                            │ │   │                     │
│  │ (Additional attack results scroll down)   │ │   │                     │
│  └────────────────────────────────────────────┘ │   │                     │
│                                                         │                     │
│  [If no attacks yet: "Click an attack button above..."] │                     │
│                                                         │                     │
└─────────────────────────────────────────────────────────┴─────────────────────┘

## Legend
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚨 = Attack detected (red color)
✅ = Attack blocked / Message accepted (green color)
👁️ = View logs (eye icon - click to toggle)
🔄 = Refresh logs (reload icon - manual fetch)
🔴 = Action button

```

## Desktop View (lg screens and up)
```
Two-column layout:
┌─────────────────────────────────┬───────────────┐
│ Left Column (66%)               │ Right Column  │
│ Attack Controls                 │ (33%)         │
│ + Results                       │ Server Logs   │
│                                 │ (Sticky)      │
│                                 │               │
│                                 │               │
└─────────────────────────────────┴───────────────┘
```

## Mobile/Tablet View (< lg)
```
Single column stacked:
┌──────────────────┐
│ Attack Controls  │
│ + Results        │
├──────────────────┤
│ Server Logs      │
│ (Below on scroll)│
└──────────────────┘
```

## Interactive Elements

### Left Column
- **Attack Buttons** (4 scenarios)
  - Click to execute an attack
  - Shows loading state while executing
  - Results appear below in real-time

- **Clear Results Button**
  - Appears when there are results
  - Clears all attack results from left panel
  - Does NOT clear server logs (they keep auto-refreshing)

- **Attack Result Cards** (Expandable)
  - Click to expand/collapse
  - Shows:
    - Attack type and description
    - Result badge (✅ BLOCKED or ❌ FAILED)
    - Protection mechanism explanation
    - Legitimate message JSON
    - Attack attempt JSON
    - Server HTTP response

### Right Column
- **Server Logs Panel** (Sticky)
  - **Eye Icon Toggle** (👁️)
    - Click to show/hide log content
    - Header always visible
    - Logs continue fetching in background
  
  - **Refresh Button** (🔄)
    - Manual refresh of logs
    - Shows loading spinner while fetching
    - Disabled during fetch
  
  - **Log Entries**
    - Color-coded by type (red/green)
    - Shows severity badge
    - Displays username, timestamp, IP
    - Max 20 most recent entries
    - Auto-scrolls to bottom when new logs arrive
    - Auto-refreshes every 2 seconds

## User Interactions

### Scenario 1: View All Attacks with Logs
1. User opens Replay Attack Demo
2. Logs panel visible on right (initially empty)
3. User clicks "Attack 1: Duplicate Nonce Replay"
4. Left panel shows attack was executed
5. Within 2 seconds, right panel shows:
   - "🚨 REPLAY_ATTACK_DETECTED" (red)
   - Username: "alice"
   - Time: "14:32:15"
   - Severity: "CRITICAL"

### Scenario 2: Compare Attack vs Legitimate
1. User clicks an attack button
2. Attack result shows on left with two JSON sections:
   - Legitimate message (passed, got stored)
   - Attack message (blocked at server)
3. User can see exact differences (same nonce, etc.)
4. User looks at right panel to see server's log entry

### Scenario 3: Monitor Multiple Attacks
1. User clicks multiple attack buttons in sequence
2. Left panel shows multiple result cards (scrollable)
3. Right panel shows multiple log entries from server
4. Each log entry has different type:
   - "REPLAY_ATTACK_DETECTED" for attacks
   - "MESSAGE_SENT" for legitimate messages
5. User can expand any result card to see details

### Scenario 4: Hide Logs While Reviewing Details
1. User expands an attack result on left to see full JSON
2. User clicks eye icon on logs panel to hide it
3. Left column expands for more space to read
4. When done, user clicks eye icon again to show logs
5. New logs may have arrived while panel was hidden

## Color Scheme

### Attack Indicators
- **Red Background** (bg-red-900 bg-opacity-30)
  - Indicates: REPLAY_ATTACK_DETECTED
  - Border: border-red-700
  - Text: text-red-300
  - Icon: 🚨

- **Green Background** (bg-green-900 bg-opacity-30)
  - Indicates: MESSAGE_SENT
  - Border: border-green-700
  - Text: text-green-300
  - Icon: ✅

- **Yellow Background** (bg-yellow-600)
  - Indicates: WARNING severity
  - Used in severity badge

- **Red Badge** (bg-red-600)
  - Indicates: CRITICAL severity

### Other Colors
- **Dark Gray** (bg-gray-800, bg-gray-900)
  - Main panel backgrounds
  - Card backgrounds

- **Light Gray** (text-gray-300, text-gray-400)
  - Normal text
  - Details text

- **Blue** (text-blue-300, text-blue-400)
  - Links and interactive elements
  - Eye icon color

## Responsive Breakpoints

### lg (1024px and up)
- Two-column layout active
- Left: 66% width (lg:col-span-2)
- Right: 33% width (lg:col-span-1)
- Logs panel sticky

### Below lg
- Single column layout
- Full width for each section
- Stacked vertically
- Logs panel below results

## Performance Considerations

1. **Auto-Refresh Rate:** Every 2 seconds
   - Configurable via useEffect interval
   - Can be increased if database gets too large

2. **Log Limit:** Last 20 entries
   - Filters for only REPLAY_ATTACK_DETECTED and MESSAGE_SENT
   - Prevents memory bloat on frontend

3. **Database Query:** `/api/logs` returns last 50 logs
   - Server-side sorting by timestamp (desc)
   - Indexed queries for fast retrieval
   - JWT token required for auth

## Accessibility

- Semantic HTML
- Proper color contrast
- Icons have title tooltips
- Keyboard navigation support
- Clear visual feedback on interactions
