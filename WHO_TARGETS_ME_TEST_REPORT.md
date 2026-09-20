# Who-Targets-Me browser-extension security test report

**Test date:** 20 September 2026  
**Target:** Who-Targets-Me browser extension  
**Pinned target commit:** `64e9989c65ba83e8536e57768e19ff0b6409abda`  
**Browser:** Google Chrome for Testing `153.0.8010.52`  
**Result:** two browser-boundary findings dynamically reproduced with synthetic data

## Finding status

These are real findings, with an important difference in the strength of the two reproductions:

| ID | Finding | What the run proves | Status |
| --- | --- | --- | --- |
| `WTM-MAP-01` | Untrusted page messages invoke privileged extension commands | Ordinary JavaScript in a matched webpage changed the extension's private `general_token` storage value through the original page → content script → service worker path. | **End-to-end reproduced vulnerability** |
| `WTM-MAP-02` | Registration credentials are exposed to the page origin | When `registrationFeedback` reaches the original content-script handler, its token is written to page-origin `localStorage` and broadcast to page JavaScript. | **Dynamically reproduced exposure sink; live token acquisition not tested** |

The safe claim is that both insecure browser-boundary behaviors exist and execute in a real browser. The run did not contact the production WhoTargetsMe API, obtain a real user token, demonstrate account takeover, or establish token lifetime and server-side impact.

## Test artifact

The complete executable test is shipped with this report:

- Script: [`scripts/test-wtm-extension-bridge.mjs`](scripts/test-wtm-extension-bridge.mjs)
- Length: 641 lines
- SHA-256: `d2016c65995cf27eae0bfb62d385fbc517c897043d785caf5930f4dcbd76dd28`
- Runtime: Node.js plus the target repository's installed `ws` dependency
- Browser requirement: Chrome for Testing, Chromium, or official Chrome older than version 137

The full script remains a separate versioned file so the executable evidence and report cannot silently diverge through a duplicated code listing. The security-relevant test actions are reproduced below.

```js
// WTM-MAP-01: execute as ordinary JavaScript in the localhost test page.
window.postMessage({ storeUserToken: true, token: marker }, "*");

// The test-only observation channel then reads chrome.storage.local from the
// disposable extension copy and waits until general_token equals marker.

// WTM-MAP-02: ask the disposable worker hook to deliver synthetic feedback
// through the extension's normal worker-to-content-script channel.
window.postMessage({
  __wtmHarnessChannel: harnessChannel,
  kind: "emit-registration",
  token: exposureMarker
}, "*");

// The page verifies both original sinks.
const observed = {
  localStorageValue: localStorage.getItem("general_token"),
  broadcastToken:
    window.__wtmHarnessMessages.at(-1)?.registrationFeedback?.token
};
```

The exact implementation is at lines 378–429 and 541–623 of the companion script.

## User-executed command

The browser was launched by the user from the harness repository, not by the analysis agent:

```bash
node scripts/test-wtm-extension-bridge.mjs --headed --skip-build
```

`--headed` displayed the temporary browser window. `--skip-build` reused the existing `Who-Targets-Me/build/chrome` artifact. The harness had previously built that artifact with `OFFLINE=true`.

## Exact observed output

```text
(hack) ebony@Ebonys-MacBook-Pro-M1 hack % node scripts/test-wtm-extension-bridge.mjs --headed --skip-build
Using browser: Google Chrome for Testing 153.0.8010.52
Launching Chrome with a temporary, isolated profile...

VULNERABLE: both browser-level checks reproduced.
{
  "WTM-MAP-01": {
    "result": "reproduced",
    "pageMessageChangedExtensionStorage": true
  },
  "WTM-MAP-02": {
    "result": "reproduced",
    "tokenWrittenToPageLocalStorage": true,
    "tokenBroadcastToPage": true
  },
  "whoTargetsMeProductionApiUsed": false,
  "profile": "temporary and isolated"
}
```

## Vulnerable production code

### Page-to-extension bridge

`Who-Targets-Me/src/contents/index.js:5-10` listens for messages from the page's own window and forwards the complete attacker-controlled value into the extension runtime:

```js
window.addEventListener("message", async function (event) {
  if (event.source != window) {
    return;
  }

  currentBrowser.runtime.sendMessage(event.data);
});
```

`event.source == window` is not authentication: messages emitted by ordinary scripts in the host page satisfy it. There is no origin policy, capability, command allowlist, or payload schema at this boundary.

### Privileged token write

`Who-Targets-Me/src/shared/handlers/onMessageEventHandler.js:53-57` trusts the forwarded command and writes the supplied value into private extension storage:

```js
} else if (request.storeUserToken) {
  await setToStorage("general_token", request.token);
}
```

This write is performed through `chrome.storage.local` in `src/shared/utils/setToStorage.js:3-9`.

### Extension-to-page credential exposure

`Who-Targets-Me/src/contents/index.js:13-17` takes registration feedback from the extension, stores the token in the website's origin storage, and broadcasts the response to the page:

```js
currentBrowser.runtime.onMessage.addListener((request) => {
  if (request.registrationFeedback) {
    localStorage.setItem(
      "general_token",
      JSON.stringify(request.registrationFeedback.token)
    );
    window.postMessage(request, "*");
    return;
  }
});
```

Content scripts use an isolated JavaScript world, but DOM storage belongs to the page origin. The run directly confirmed that page JavaScript could read the written value and receive the message.

## End-to-end evidence chain

### WTM-MAP-01

```text
ordinary localhost page JavaScript
  → window.postMessage({storeUserToken, token})
  → original content-script window message listener
  → runtime.sendMessage(event.data)
  → original privileged background handler
  → chrome.storage.local.set({general_token: marker})
  → test-only readback observes the identical marker
```

The test-only code observes the final state. It does not perform or replace the vulnerable forwarding or privileged write. This is an end-to-end confirmation of an integrity violation at the page-to-extension trust boundary.

### WTM-MAP-02

```text
test-only worker hook creates synthetic registrationFeedback
  → normal chrome.tabs.sendMessage path
  → original content-script registrationFeedback handler
  → page-origin localStorage receives the marker
  → original window.postMessage(..., "*") broadcasts the marker
  → ordinary page JavaScript observes both copies
```

The hook substitutes for the production registration/API step. It does not substitute for either exposure sink. Therefore, the test proves the unsafe credential handling but not the ability to obtain a live production credential.

## Isolation and safety properties

The harness:

- uses a newly created temporary Chrome profile;
- copies the built extension into a temporary directory before instrumentation;
- uses random marker tokens and a random observation-channel identifier;
- serves only a synthetic localhost page;
- builds with `OFFLINE=true` unless `--skip-build` is used;
- maps external DNS to failure while excluding localhost;
- disables Chrome background networking, component updates, and sync;
- does not send a request to the WhoTargetsMe production API;
- terminates Chrome and removes the temporary profile and extension copy after the run.

No real user credential is required or collected.

## Why the temporary instrumentation does not manufacture the findings

The copied extension receives a random-channel test hook for three purposes:

1. prove that the extension loaded and the content script injected;
2. read `general_token` back from extension storage after the page's forged command;
3. send synthetic `registrationFeedback` through the real worker-to-content-script channel.

The hook deliberately does not handle `storeUserToken`, forward arbitrary page messages, write the marker into extension storage, write a registration token into page `localStorage`, or broadcast registration feedback with `targetOrigin="*"`. Each of those security-relevant actions is performed by the original target code.

This makes WTM-MAP-01 a strong end-to-end reproduction. WTM-MAP-02 is a focused dynamic reproduction of the exposure sink, with the upstream production API step replaced by a safe synthetic source.

## Attacker prerequisites and plausible impact

### WTM-MAP-01

The attacker needs JavaScript execution in a page matched by the extension's content-script rules. That may be the site's own code, an included third-party script, a malicious page on a matched origin, or an independent page-level injection flaw. The manifest includes broad, high-value sites such as Google, Facebook, Instagram, X, YouTube, WhoTargetsMe, and localhost.

The reproduced impact is unauthorized modification of extension authentication state. Possible downstream effects include session fixation, account confusion, state deletion, forged registration or consent operations, and attacker-shaped telemetry. Those downstream effects were not tested and depend on backend token semantics and command-specific controls.

### WTM-MAP-02

Any script executing in the receiving page origin can read the token from `localStorage` or listen for the broadcast message. The source also routes registration feedback through the active tab rather than clearly binding it to the initiating tab and frame.

The reproduced impact is disclosure to page JavaScript. Token replay, account takeover, token duration, and the ability to induce a live registration response remain open questions.

## Limitations

- Only the `storeUserToken` privileged command was dynamically exercised. Other reachable commands need separate tests before claiming their effects.
- The production registration endpoint was intentionally not contacted.
- The test used the repository's local build at the pinned commit, not a Chrome Web Store package.
- WTM-MAP-02 used a synthetic extension-side message; it confirms the sink rather than the complete server-to-page chain.
- The current harness records its result to stdout. A future pipeline should persist a structured `Experiment`, raw output, environment metadata, and a `Finding` artifact under the run directory.
- The test should gain a formal benign control and be repeated from a clean build as part of a final disclosure package.

## Recommended remediation

1. Remove the generic page-message-to-runtime bridge.
2. Do not expose token, registration, deletion, consent, or telemetry commands to page-controlled messages.
3. If page integration is required, define a minimal schema and command allowlist, validate the expected origin and frame, and require an unguessable per-session capability established by the extension.
4. Bind every response to the initiating tab, frame, origin, and request identifier instead of the currently active tab.
5. Keep credentials exclusively in extension storage. Never place reusable credentials in page-origin `localStorage` or wildcard `postMessage` payloads.
6. Add regression tests proving page scripts cannot change extension authentication state or observe registration credentials.

## Conclusion

`WTM-MAP-01` is a real, dynamically reproduced privilege-boundary vulnerability: untrusted webpage JavaScript changed privileged extension storage through the extension's original message-handling path.

`WTM-MAP-02` is also a real insecure behavior: the original handler exposes registration tokens to the page origin. The exposure itself is dynamically confirmed, while the acquisition and impact of a live production token remain intentionally unverified. It should be reported with that limitation rather than presented as a demonstrated account takeover.
