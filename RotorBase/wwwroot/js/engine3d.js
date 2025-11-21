import * as THREE from "https://unpkg.com/three@0.180.0/build/three.module.js?module";
import { GLTFLoader } from "https://unpkg.com/three@0.180.0/examples/jsm/loaders/GLTFLoader.js?module";
import { OrbitControls } from "https://unpkg.com/three@0.180.0/examples/jsm/controls/OrbitControls.js?module";

const INSTANCES = new Map();
const PART_CACHE = new Map();
let CURRENT_STATE = null;
let dotnetRef = null;

const knownSocketNames = new Set();

const DEBUG_STORAGE_KEY = "engine3d:debug";
let GLOBAL_DEBUG = false;

function applyGlobalDebug(enabled) {
  const normalized = !!enabled;
  if (GLOBAL_DEBUG === normalized) {
    return;
  }

  GLOBAL_DEBUG = normalized;
  if (typeof window !== "undefined") {
    try {
      if (GLOBAL_DEBUG) {
        window.localStorage?.setItem(DEBUG_STORAGE_KEY, "1");
      } else {
        window.localStorage?.removeItem(DEBUG_STORAGE_KEY);
      }
    } catch (err) {
      console.warn("engine3d: failed to persist debug preference", err);
    }
  }
  console.info("engine3d: debug mode", GLOBAL_DEBUG ? "enabled" : "disabled");
}

(function initializeDebug() {
  if (typeof window === "undefined") {
    return;
  }

  try {
    const stored = window.localStorage?.getItem(DEBUG_STORAGE_KEY);
    if (stored === "1") {
      GLOBAL_DEBUG = true;
    }

    const debugParam = new URL(window.location.href).searchParams.get("debug");
    if (debugParam === "1") {
      applyGlobalDebug(true);
    } else if (debugParam === "0") {
      applyGlobalDebug(false);
    }
  } catch (err) {
    console.warn("engine3d: debug initialization failed", err);
  }

  window.Engine3D = Object.assign(window.Engine3D || {}, {
    setDebug(value) {
      applyGlobalDebug(value);
    },
    getDebug() {
      return GLOBAL_DEBUG;
    }
  });
})();

const DEFAULT_OPTIONS = {
  glbPath: "/assets/engine/engine-a.glb",
  socketPrefix: "Socket_",
  buildId: null,
  backgroundColor: 0xf8fafc,
  gizmoColor: 0x3b82f6,
  gizmoHoverColor: 0x6677ff,
  slotStatusEndpoint: "/api/builds/{buildId}/slots/status",
  badgeEndpoint: "/api/builds/{buildId}/badges",
  clearEndpoint: "/api/builds/clear"
};

const DEFAULT_ALWAYS_VISIBLE_NODES = new Set(["Ground", "Grid", "Backdrop"]);

function hideBaseMeshes(root, state) {
  if (!root) return;
  const allow = new Set(DEFAULT_ALWAYS_VISIBLE_NODES);
  const extras = state?.options?.alwaysVisibleNodes;
  if (Array.isArray(extras)) {
    for (const name of extras) {
      if (typeof name === "string" && name.trim()) {
        allow.add(name);
      }
    }
  }

  root.traverse(obj => {
    if (!obj?.isMesh) return;
    if (obj.name && allow.has(obj.name)) return;
    obj.visible = false;
  });
}

function isDebugEnabled(state) {
  if (state && typeof state.debug === "boolean") {
    return state.debug;
  }
  return GLOBAL_DEBUG;
}

function debugLog(state, ...args) {
  if (isDebugEnabled(state)) {
    console.info("engine3d:", ...args);
  }
}

function debugWarn(state, ...args) {
  console.warn("engine3d:", ...args);
}

function attachDebugOverlay(state) {
  if (!isDebugEnabled(state)) return;

  const container = state?.container;
  if (!container) return;

  if (!state.debugOverlay) {
    const computed = typeof window !== "undefined" ? window.getComputedStyle(container) : null;
    state.debugOriginalPosition = container.style.position || "";
    if (computed && computed.position === "static") {
      container.style.position = "relative";
      state.debugPositionAdjusted = true;
    }

    const overlay = document.createElement("div");
    overlay.className = "engine3d-debug-panel";
    overlay.style.position = "absolute";
    overlay.style.top = "8px";
    overlay.style.left = "8px";
    overlay.style.zIndex = "1000";
    overlay.style.background = "rgba(15,23,42,0.85)";
    overlay.style.color = "#f8fafc";
    overlay.style.fontSize = "11px";
    overlay.style.fontFamily = "monospace";
    overlay.style.padding = "6px 8px";
    overlay.style.borderRadius = "6px";
    overlay.style.pointerEvents = "none";
    overlay.style.maxWidth = "260px";
    container.appendChild(overlay);
    state.debugOverlay = overlay;
  }

  updateDebugOverlay(state, { status: "mounting", glbPath: state?.options?.glbPath });
}

function updateDebugOverlay(state, info = {}) {
  if (!state?.debugOverlay) return;
  state.debugMetrics = { ...(state.debugMetrics || {}), ...info };
  const metrics = state.debugMetrics;
  const socketPreview = Array.isArray(metrics.socketPreview)
    ? metrics.socketPreview.join(", ")
    : metrics.socketPreview || "";
  const lines = [
    "<strong>Engine3D Debug</strong>",
    `GLB: ${metrics.glbPath || "n/a"}`,
    `Nodes: ${metrics.nodeCount ?? "?"} | Sockets: ${metrics.socketCount ?? "?"}`,
    `Last socket: ${metrics.lastSocket || "—"}`,
    `Last action: ${metrics.lastAction || "—"}`,
    socketPreview ? `Sockets: ${socketPreview}` : "",
    metrics.lastError ? `<span style=\"color:#fda4af\">Error: ${metrics.lastError}</span>` : ""
  ].filter(Boolean);

  state.debugOverlay.innerHTML = lines.join("<br/>");
}

function detachDebugOverlay(state) {
  if (!state) return;
  if (state.debugOverlay && state.debugOverlay.parentElement) {
    state.debugOverlay.parentElement.removeChild(state.debugOverlay);
  }
  state.debugOverlay = null;
  if (state.debugPositionAdjusted && state.container) {
    state.container.style.position = state.debugOriginalPosition || "";
  }
  state.debugPositionAdjusted = false;
  state.debugMetrics = {};
}

function resolveElement(target) {
  if (!target) return null;
  if (typeof target === "string") return document.querySelector(target);
  if (target instanceof HTMLElement) return target;
  return null;
}

function disposeObject3D(obj) {
  obj.traverse(child => {
    if (child.isMesh) {
      child.geometry?.dispose?.();
      if (Array.isArray(child.material)) {
        child.material.forEach(mat => mat?.dispose?.());
      } else {
        child.material?.dispose?.();
      }
    }
  });
}

function isBadgeComplete(payload) {
  if (payload == null) return false;
  if (typeof payload === "boolean") return payload;
  if (typeof payload === "number") return payload > 0;
  if (typeof payload === "string") return payload.includes("✅") || payload.toLowerCase() === "ok";
  if (typeof payload.local_ok !== "undefined") return !!payload.local_ok;
  if (typeof payload.badge === "string") return payload.badge.includes("✅") || payload.badge.toLowerCase() === "ok";
  if (typeof payload.status === "string") return payload.status.toLowerCase() === "complete";
  if (typeof payload.selected_count !== "undefined" && typeof payload.min_required !== "undefined" && typeof payload.capacity !== "undefined") {
    const cnt = Number(payload.selected_count) || 0;
    return cnt >= Number(payload.min_required || 0) && cnt <= Number(payload.capacity ?? cnt);
  }
  return false;
}

function makeGizmo(color, hoverColor) {
  const group = new THREE.Group();
  const geom = new THREE.SphereGeometry(0.015, 16, 16);
  const mat = new THREE.MeshStandardMaterial({
    color,
    transparent: true,
    opacity: 0.65
  });
  const mesh = new THREE.Mesh(geom, mat);
  mesh.userData.baseColor = new THREE.Color(color);
  mesh.userData.highlight = new THREE.Color(hoverColor ?? DEFAULT_OPTIONS.gizmoHoverColor);
  group.add(mesh);

  const hitGeom = new THREE.SphereGeometry(0.03, 8, 8);
  const hitMat = new THREE.MeshBasicMaterial({ visible: false });
  const hitMesh = new THREE.Mesh(hitGeom, hitMat);
  hitMesh.userData.tag = "socket-hit";
  group.add(hitMesh);

  return { group, mesh, hit: hitMesh };
}

function setHovered(state, gizmo) {
  if (state.hovered === gizmo) return;

  if (state.hovered) {
    const prevMesh = state.hovered.children[0];
    if (prevMesh?.material?.color && prevMesh.userData.baseColor) {
      prevMesh.material.color.copy(prevMesh.userData.baseColor);
    }
  }

  state.hovered = gizmo ?? null;

  if (state.hovered) {
    const mesh = state.hovered.children[0];
    if (mesh?.material?.color) {
      if (mesh.userData.highlight) {
        mesh.material.color.copy(mesh.userData.highlight);
      } else {
        mesh.material.color.offsetHSL(0, 0.1, 0.1);
      }
    }
    state.renderer.domElement.style.cursor = "pointer";
  } else {
    state.renderer.domElement.style.cursor = "default";
  }
}

function setSocketBadgeInternal(state, socketName, ok) {
  if (!state) return;
  const entry = state.gizmosBySocket.get(socketName);
  if (!entry) return;
  const mesh = entry.mesh;
  const color = ok ? 0x22aa55 : 0xcc3344;
  mesh.material.color.setHex(color);
  mesh.userData.baseColor = new THREE.Color(color);
  if (mesh.material.emissive) {
    mesh.material.emissive.setHex(ok ? 0x114422 : 0x441111);
  }
  state.badges.set(socketName, !!ok);
}

function registerSocketGizmo(state, socketName, group, mesh) {
  state.gizmosBySocket.set(socketName, { group, mesh });
}

function getBuildId(state = CURRENT_STATE) {
  return state?.options?.buildId ?? 0;
}

function attachEvents(state) {
  const { renderer, camera, raycaster, mouse, socketHits } = state;
  const canvas = renderer.domElement;

  state.pointerHandler = event => {
    const rect = canvas.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    const hits = raycaster.intersectObjects(socketHits, false);
    if (hits.length > 0) {
      setHovered(state, hits[0].object.parent);
    } else {
      setHovered(state, null);
    }
  };

  state.clickHandler = async event => {
    if (!state.hovered) return;
    const socketName = state.hovered.userData.socketName;
    if (!socketName) return;

    if (event.shiftKey) {
      try {
        await clearSocketSelection(socketName, state);
      } catch (err) {
        console.error("engine3d: failed to clear socket", err);
      }
      return;
    }

    if (dotnetRef && typeof dotnetRef.invokeMethodAsync === "function") {
      try {
        await dotnetRef.invokeMethodAsync("FocusCategoryForSocket", socketName);
      } catch (err) {
        debugWarn(state, "focus category callback failed", err);
      }
    } else {
      blinkSocketByPath(socketName);
    }
  };

  state.resizeHandler = () => {
    const { clientWidth, clientHeight } = state.container;
    if (clientWidth === 0 || clientHeight === 0) return;
    state.camera.aspect = clientWidth / clientHeight;
    state.camera.updateProjectionMatrix();
    state.renderer.setSize(clientWidth, clientHeight, false);
  };

  canvas.addEventListener("pointermove", state.pointerHandler);
  canvas.addEventListener("click", state.clickHandler);
  window.addEventListener("resize", state.resizeHandler);

  state.resizeObserver = new ResizeObserver(() => state.resizeHandler());
  state.resizeObserver.observe(state.container);
}

function detachEvents(state) {
  const canvas = state.renderer?.domElement;
  if (canvas && state.pointerHandler) {
    canvas.removeEventListener("pointermove", state.pointerHandler);
  }
  if (canvas && state.clickHandler) {
    canvas.removeEventListener("click", state.clickHandler);
  }
  if (state.resizeHandler) {
    window.removeEventListener("resize", state.resizeHandler);
  }
  if (state.resizeObserver) {
    state.resizeObserver.disconnect();
  }
}

function animate(state) {
  state.controls.update();
  state.renderer.render(state.scene, state.camera);
  state.frameId = requestAnimationFrame(() => animate(state));
}

function findNodeByName(root, name) {
  let found = null;
  if (!root) return found;
  root.traverse(obj => {
    if (!found && obj.name === name) {
      found = obj;
    }
  });
  return found;
}

function findAttachNode(root, preferredName) {
  if (!root) return null;

  const candidates = [];
  if (preferredName) {
    candidates.push(preferredName);
  }
  candidates.push("Attach_Main", "Attach");

  const locate = target => {
    let match = null;
    root.traverse(obj => {
      if (!match && obj?.name) {
        if (obj.name === target || obj.name.startsWith(`${target}.`)) {
          match = obj;
        }
      }
    });
    return match;
  };

  for (const candidate of candidates) {
    const hit = locate(candidate);
    if (hit) return hit;
  }

  let flagged = null;
  root.traverse(obj => {
    if (flagged || !obj) return;
    const tag = obj.userData?.attach ?? obj.userData?.Attach ?? obj.userData?.attachNode;
    if (typeof tag === "string" && tag.length) {
      if (candidates.some(name => tag === name || tag.startsWith(`${name}.`))) {
        flagged = obj;
      }
    } else if (tag === true) {
      flagged = obj;
    }
  });
  if (flagged) return flagged;

  let firstMesh = null;
  root.traverse(obj => {
    if (!firstMesh && obj?.isMesh) {
      firstMesh = obj;
    }
  });
  return firstMesh;
}

async function loadPartAsset(uri, state) {
  if (!uri) throw new Error("Missing GLTF URI for part");
  if (PART_CACHE.has(uri)) {
    return PART_CACHE.get(uri);
  }
  const loader = state.partLoader ?? (state.partLoader = new GLTFLoader());
  const gltf = await loader.loadAsync(uri);
  PART_CACHE.set(uri, gltf);
  return gltf;
}

function removePartAtSocket(socketName, state) {
  const existing = state.placedBySocket.get(socketName);
  if (existing && existing.parent) {
    existing.parent.remove(existing);
    disposeObject3D(existing);
  }
  state.placedBySocket.delete(socketName);
  state.selectedPartBySocket.delete(socketName);
}

async function placePartAtSocketInternal(part, socketName, state = CURRENT_STATE) {
  if (!state) {
    debugWarn(state, "no active state to place part");
    return null;
  }
  if (!state.engineRoot) {
    debugWarn(state, "engine root not ready");
    return null;
  }

  updateDebugOverlay(state, {
    lastSocket: socketName,
    lastAction: "place-part",
    lastActionAt: new Date().toISOString()
  });
  debugLog(state, { action: "place-part", socket: socketName, uri: part?.uri });

  const gltf = await loadPartAsset(part.uri, state);
  const partRoot = gltf.scene.clone(true);

  const socketNode = findNodeByName(state.engineRoot, socketName);
  if (!socketNode) {
    debugWarn(state, "socket node not found", socketName);
    updateDebugOverlay(state, {
      lastSocket: socketName,
      lastAction: "place-part-error",
      lastError: `Socket not found: ${socketName}`
    });
    return null;
  }

  const attachName = part.attachNode || "Attach_Main";
  const attachNode = findAttachNode(partRoot, attachName);
  if (!attachNode) {
    debugWarn(state, "attach node not found on part", attachName);
    updateDebugOverlay(state, {
      lastSocket: socketName,
      lastAction: "place-part-error",
      lastError: `Attach node not found: ${attachName}`
    });
    return null;
  }

  state.engineRoot.updateWorldMatrix(true, true);
  partRoot.updateMatrixWorld(true);
  attachNode.updateMatrixWorld(true);
  socketNode.updateMatrixWorld(true, true);

  const socketMatrix = socketNode.matrixWorld.clone();
  const attachMatrix = attachNode.matrixWorld.clone();
  const delta = new THREE.Matrix4().multiplyMatrices(socketMatrix, attachMatrix.invert());

  removePartAtSocket(socketName, state);

  partRoot.matrixAutoUpdate = false;
  partRoot.matrix.identity();
  partRoot.applyMatrix4(delta);
  partRoot.updateMatrixWorld(true);
  partRoot.userData.socketName = socketName;

  state.engineRoot.add(partRoot);
  state.placedBySocket.set(socketName, partRoot);
  updateDebugOverlay(state, {
    lastSocket: socketName,
    lastAction: "place-part-success",
    lastError: null
  });
  debugLog(state, { action: "place-part-success", socket: socketName, uri: part?.uri });
  return partRoot;
}

function resolveSocketName(row, state = CURRENT_STATE) {
  if (!row) return null;
  const prefix = state?.options?.socketPrefix || DEFAULT_OPTIONS.socketPrefix;
  if (row.gltf_node_path) {
    const parts = String(row.gltf_node_path).split("/");
    const match = parts.find(segment => segment && segment.startsWith(prefix));
    if (match) return match;
  }
  if (row.slot_key) {
    return `${prefix}${row.slot_key}`;
  }
  debugWarn(state, "resolveSocketName: unable to resolve socket name", {
    slotId: row.slot_id ?? row.SlotId,
    slotKey: row.slot_key ?? row.SlotKey,
    gltfNodePath: row.gltf_node_path ?? row.GltfNodePath
  });
  return null;
}

function normalizeSocketLookupKey(value) {
  if (!value && value !== 0) return "";
  return String(value)
    .trim()
    .replace(/[\s_]+/g, "_")
    .toLowerCase();
}

function getSocketNameFromPath(socketPath, state = CURRENT_STATE) {
  if (!socketPath) return null;
  const prefix = state?.options?.socketPrefix || DEFAULT_OPTIONS.socketPrefix;
  const segments = String(socketPath)
    .replace(/\\/g, "/")
    .split("/")
    .map(part => part.trim())
    .filter(Boolean);
  if (!segments.length) return null;

  const prefixed = segments.find(segment => segment.startsWith(prefix));
  if (prefixed) return prefixed;

  if (state?.socketNodes?.size) {
    const normalizedSegments = segments.map(normalizeSocketLookupKey);
    for (const key of state.socketNodes.keys()) {
      const normalizedKey = normalizeSocketLookupKey(key);
      if (normalizedSegments.includes(normalizedKey)) {
        return key;
      }
    }
  }

  if (knownSocketNames.size) {
    const normalizedSegments = segments.map(normalizeSocketLookupKey);
    for (const known of knownSocketNames) {
      const normalizedKnown = normalizeSocketLookupKey(known);
      if (normalizedSegments.includes(normalizedKnown)) {
        return known;
      }
    }
  }

  return segments[segments.length - 1] || null;
}

function findSocketNodeFlexible(socketPath, state = CURRENT_STATE) {
  if (!state || !socketPath) return null;
  const socketName = getSocketNameFromPath(socketPath, state);
  if (!socketName) return null;

  const targetKey = normalizeSocketLookupKey(socketName);
  const { socketNodes, engineRoot } = state;

  if (socketNodes?.size) {
    for (const [key, node] of socketNodes.entries()) {
      if (!node?.name) continue;
      const normalizedKey = normalizeSocketLookupKey(key);
      if (normalizedKey === targetKey) {
        return node;
      }
      const normalizedNodeName = normalizeSocketLookupKey(node.name);
      if (normalizedNodeName === targetKey) {
        return node;
      }
    }
  }

  if (engineRoot) {
    let fallback = null;
    engineRoot.traverse(obj => {
      if (fallback || !obj?.name) return;
      const normalizedName = normalizeSocketLookupKey(obj.name);
      if (normalizedName === targetKey) {
        fallback = obj;
      }
    });
    if (fallback) {
      return fallback;
    }
  }

  return null;
}

async function fetchBadgeState(state = CURRENT_STATE) {
  const buildId = getBuildId(state);
  if (!buildId) return null;
  let endpoint = state.options.badgeEndpoint || DEFAULT_OPTIONS.badgeEndpoint;
  endpoint = endpoint.replace("{buildId}", buildId);

  const response = await fetch(endpoint, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status}: ${text}`);
  }
  const json = await response.json();
  updateDebugOverlay(state, {
    lastFetch: new Date().toISOString(),
    slotCount: Array.isArray(json?.slots) ? json.slots.length : 0,
    lastError: null
  });
  debugLog(state, { action: "badge-state", slots: Array.isArray(json?.slots) ? json.slots.length : "unknown" });
  return json;
}

function applyBadgeColors(data, state) {
  if (!data?.slots) return;
  for (const slot of data.slots) {
    const socketName = resolveSocketName(slot, state);
    if (!socketName) continue;
    const ok = !!slot.local_ok;
    setSocketBadgeInternal(state, socketName, ok);
  }
}

function applyHints(data, state) {
  if (!data?.hints) return;
  const requires = data.hints.requires;
  if (Array.isArray(requires) && requires.length) {
    hintRequires(requires, state);
  }
  const matchAttr = data.hints.match_attr;
  if (Array.isArray(matchAttr) && matchAttr.length) {
    hintMismatch(matchAttr, state);
  }
  const excludes = data.hints.excludes;
  if (Array.isArray(excludes) && excludes.length) {
    hintExcludes(excludes, state);
  }
}

function drawRingAtSocket(socketName, state, color = 0xcc3344, ttlMs = 900) {
  const entry = state?.gizmosBySocket.get(socketName);
  if (!entry) return;
  const ring = new THREE.Mesh(
    new THREE.TorusGeometry(0.035, 0.003, 8, 24),
    new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.8 })
  );
  ring.rotation.x = Math.PI / 2;
  entry.group.add(ring);
  setTimeout(() => {
    entry.group.remove(ring);
    disposeObject3D(ring);
  }, ttlMs);
}

function hintRequires(socketNames, state = CURRENT_STATE) {
  if (!state || !Array.isArray(socketNames)) return;
  socketNames.forEach(name => drawRingAtSocket(name, state));
}

function hintMismatch(socketNames, state = CURRENT_STATE) {
  if (!state || !Array.isArray(socketNames)) return;
  socketNames.forEach(name => {
    const entry = state?.gizmosBySocket.get(name);
    if (!entry) return;
    const pulse = new THREE.Mesh(
      new THREE.SphereGeometry(0.02, 16, 16),
      new THREE.MeshBasicMaterial({ color: 0xff9900, transparent: true, opacity: 0.7 })
    );
    entry.group.add(pulse);
    setTimeout(() => {
      entry.group.remove(pulse);
      disposeObject3D(pulse);
    }, 1000);
  });
}

function hintExcludes(socketNames, state = CURRENT_STATE) {
  if (!state || !Array.isArray(socketNames)) return;
  socketNames.forEach(name => drawRingAtSocket(name, state, 0xff3355, 1100));
}

async function publishBadgeState(data) {
  if (!dotnetRef || typeof dotnetRef.invokeMethodAsync !== "function") return;
  try {
    await dotnetRef.invokeMethodAsync("OnBadgeState", data ?? {});
  } catch (err) {
    console.warn("engine3d: badge publish failed", err);
  }
}

export async function hydrateFromServer() {
  const state = CURRENT_STATE;
  if (!state) return;
  const buildId = getBuildId(state);
  if (!buildId) return;
  if (state.readyPromise) {
    await state.readyPromise;
  }
  if (!state.engineRoot) {
    return;
  }

  updateDebugOverlay(state, { status: "hydrate" });

  let data;
  try {
    data = await fetchBadgeState(state);
  } catch (err) {
    console.error("engine3d: failed to hydrate", err);
    debugWarn(state, "hydrate failed", err);
    updateDebugOverlay(state, { lastError: err?.message || "Badge hydrate failed" });
    return;
  }

  state.placedBySocket.forEach((_node, socketName) => removePartAtSocket(socketName, state));

  if (Array.isArray(data?.slots)) {
    knownSocketNames.clear();
    for (const slot of data.slots) {
      const gltfNodePath = slot?.gltf_node_path;
      if (gltfNodePath) {
        const rawPath = String(gltfNodePath);
        knownSocketNames.add(rawPath);
        knownSocketNames.add(rawPath.replace(/ /g, "_"));
        knownSocketNames.add(rawPath.replace(/_/g, " "));
      }

      const socketName = resolveSocketName(slot, state);
      if (!socketName) continue;
      const nameVariant = String(socketName);
      knownSocketNames.add(nameVariant);
      knownSocketNames.add(nameVariant.replace(/ /g, "_"));
      knownSocketNames.add(nameVariant.replace(/_/g, " "));
      const ok = !!slot.local_ok;
      setSocketBadgeInternal(state, socketName, ok);

      if (slot.part_id && slot.gltf_uri) {
        try {
          await placePartAtSocketInternal({
            uri: slot.gltf_uri,
            attachNode: slot.gltf_attach_node || "Attach_Main"
          }, socketName, state);
          state.selectedPartBySocket.set(socketName, Number(slot.part_id));
        } catch (err) {
          console.error("engine3d: failed to hydrate part", err);
        }
      } else {
        state.selectedPartBySocket.delete(socketName);
      }
    }
  }

  applyHints(data, state);
  await publishBadgeState(data);
  updateDebugOverlay(state, { status: "hydrated" });
}

export async function refreshBadges() {
  const state = CURRENT_STATE;
  if (!state) return;
  updateDebugOverlay(state, { status: "refresh" });
  let data;
  try {
    data = await fetchBadgeState(state);
  } catch (err) {
    console.error("engine3d: failed to refresh badges", err);
    debugWarn(state, "refresh badges failed", err);
    updateDebugOverlay(state, { lastError: err?.message || "Badge refresh failed" });
    return;
  }

  applyBadgeColors(data, state);

  if (Array.isArray(data?.slots)) {
    for (const slot of data.slots) {
      const socketName = resolveSocketName(slot, state);
      if (!socketName) continue;
      if (slot.part_id) {
        state.selectedPartBySocket.set(socketName, Number(slot.part_id));
      } else {
        state.selectedPartBySocket.delete(socketName);
      }
    }
  }

  applyHints(data, state);
  await publishBadgeState(data);
  updateDebugOverlay(state, { status: "refreshed" });
}

async function clearSocketSelection(socketName, state = CURRENT_STATE) {
  if (!state) {
    debugWarn(state, "no active state to clear socket");
    return;
  }

  const buildId = getBuildId(state);
  if (!buildId) {
    return;
  }

  removePartAtSocket(socketName, state);
  updateDebugOverlay(state, {
    lastSocket: socketName,
    lastAction: "clear-socket",
    lastActionAt: new Date().toISOString()
  });
  debugLog(state, { action: "clear-socket", socket: socketName });

  try {
    const response = await fetch(state.options.clearEndpoint || DEFAULT_OPTIONS.clearEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ buildId, socketKey: socketName })
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Clear failed (${response.status}): ${text}`);
    }

    await refreshBadges();
  } catch (err) {
    console.error("engine3d: clear socket failed", err);
    debugWarn(state, "clear socket failed", err);
    updateDebugOverlay(state, {
      lastSocket: socketName,
      lastAction: "clear-socket-error",
      lastError: err?.message || "Clear failed"
    });
    await hydrateFromServer();
    throw err;
  }
}

function createState(container, options) {
  const debugFlag = typeof options.debug === "boolean" ? options.debug : GLOBAL_DEBUG;
  if (debugFlag && !GLOBAL_DEBUG) {
    applyGlobalDebug(true);
  }

  const state = {
    container,
    options,
    debug: debugFlag,
    debugOverlay: null,
    debugMetrics: {},
    debugOriginalPosition: "",
    debugPositionAdjusted: false,
    scene: new THREE.Scene(),
    renderer: null,
    camera: null,
    controls: null,
    loader: new GLTFLoader(),
    partLoader: new GLTFLoader(),
    raycaster: new THREE.Raycaster(),
    mouse: new THREE.Vector2(),
    socketGizmos: [],
    socketHits: [],
    socketNodes: new Map(),
    gizmosBySocket: new Map(),
    placedBySocket: new Map(),
    selectedPartBySocket: new Map(),
    badges: new Map(),
    hovered: null,
    frameId: null,
    engineRoot: null,
    pointerHandler: null,
    clickHandler: null,
    resizeHandler: null,
    resizeObserver: null,
    readyPromise: null,
    resolveReady: null
  };

  state.scene.background = new THREE.Color(options.backgroundColor);
  state.readyPromise = new Promise(resolve => {
    state.resolveReady = resolve;
  });

  return state;
}

export function mountEngineScene(target, options = {}) {
  const container = resolveElement(target);
  if (!container) {
    console.warn("engine3d: container not found", target);
    return;
  }

  disposeEngineScene(container);

  const opts = { ...DEFAULT_OPTIONS, ...options };
  if (typeof opts.debug !== "boolean") {
    opts.debug = GLOBAL_DEBUG;
  }

  const state = createState(container, opts);

  attachDebugOverlay(state);
  debugLog(state, { action: "mount", glbPath: opts.glbPath, buildId: opts.buildId });
  updateDebugOverlay(state, { status: "loading", glbPath: opts.glbPath });

  const width = container.clientWidth || container.offsetWidth || 640;
  const height = container.clientHeight || container.offsetHeight || 480;

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setSize(width, height, false);
  renderer.outputEncoding = THREE.sRGBEncoding;
  container.appendChild(renderer.domElement);
  renderer.domElement.style.width = "100%";
  renderer.domElement.style.height = "100%";

  const camera = new THREE.PerspectiveCamera(55, width / height, 0.05, 100);
  camera.position.set(1.8, 1.2, 2.2);

  const controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;

  const hemi = new THREE.HemisphereLight(0xffffff, 0x222233, 1.0);
  state.scene.add(hemi);
  const dir = new THREE.DirectionalLight(0xffffff, 1.0);
  dir.position.set(3, 3, 3);
  state.scene.add(dir);

  state.renderer = renderer;
  state.camera = camera;
  state.controls = controls;

  attachEvents(state);
  animate(state);

  state.loader.load(
    opts.glbPath,
    gltf => {
      state.engineRoot = gltf.scene;
      state.scene.add(state.engineRoot);
      hideBaseMeshes(state.engineRoot, state);

      let nodeCount = 0;
      const socketNames = [];

      state.engineRoot.traverse(obj => {
        nodeCount += 1;
        if (!obj.name || !obj.name.startsWith(opts.socketPrefix)) {
          return;
        }
        state.socketNodes.set(obj.name, obj);
        socketNames.push(obj.name);
        obj.updateWorldMatrix(true, false);
        const worldPos = new THREE.Vector3().setFromMatrixPosition(obj.matrixWorld);
        const gizmoParts = makeGizmo(opts.gizmoColor, opts.gizmoHoverColor);
        gizmoParts.group.position.copy(worldPos);
        gizmoParts.group.userData.socketName = obj.name;
        gizmoParts.group.userData.socketNode = obj;
        state.scene.add(gizmoParts.group);
        state.socketGizmos.push(gizmoParts.group);
        state.socketHits.push(gizmoParts.hit);
        registerSocketGizmo(state, obj.name, gizmoParts.group, gizmoParts.mesh);
      });

      socketNames.sort((a, b) => a.localeCompare(b));

      if (!state.socketGizmos.length) {
        debugWarn(state, "no sockets found; ensure nodes are named with", opts.socketPrefix);
        updateDebugOverlay(state, {
          glbPath: opts.glbPath,
          nodeCount,
          socketCount: 0,
          lastError: "No sockets found in GLB"
        });
      } else {
        updateDebugOverlay(state, {
          glbPath: opts.glbPath,
          nodeCount,
          socketCount: socketNames.length,
          socketPreview: socketNames.slice(0, 12),
          lastError: null
        });
        debugLog(state, `sockets found (${socketNames.length})`, socketNames);
      }

      updateDebugOverlay(state, { status: "ready" });
      state.resolveReady?.(state);
    },
    undefined,
    error => {
      console.error("engine3d: failed to load engine GLB", error);
      debugWarn(state, "failed to load engine GLB", error);
      updateDebugOverlay(state, { lastError: error?.message || "GLB load failed" });
      state.resolveReady?.(state);
    }
  );

  INSTANCES.set(container, state);
  CURRENT_STATE = state;
}

export function disposeEngineScene(target) {
  const container = resolveElement(target);
  if (!container) return;

  const state = INSTANCES.get(container);
  if (!state) return;

  detachDebugOverlay(state);

  setHovered(state, null);
  cancelAnimationFrame(state.frameId);
  detachEvents(state);

  if (state.placedBySocket) {
    for (const node of state.placedBySocket.values()) {
      if (node?.parent) {
        node.parent.remove(node);
      }
      disposeObject3D(node);
    }
    state.placedBySocket.clear();
    state.selectedPartBySocket.clear();
  }

  if (state.socketGizmos.length) {
    for (const gizmo of state.socketGizmos) {
      disposeObject3D(gizmo);
      state.scene.remove(gizmo);
    }
  }

  if (state.engineRoot) {
    disposeObject3D(state.engineRoot);
    state.scene.remove(state.engineRoot);
  }

  state.controls?.dispose?.();
  state.renderer?.dispose?.();

  if (state.renderer?.domElement?.parentElement === container) {
    container.removeChild(state.renderer.domElement);
  }

  INSTANCES.delete(container);
  if (CURRENT_STATE === state) {
    CURRENT_STATE = null;
  }
}

export function setBuildContext(buildId) {
  if (CURRENT_STATE) {
    CURRENT_STATE.options.buildId = buildId ?? 0;
  }
}

export function setDotNetRef(ref) {
  dotnetRef = ref || null;
}

export function setDebugMode(enabled) {
  applyGlobalDebug(enabled);
}

export async function placePartAtSocket(part, socketName) {
  return placePartAtSocketInternal(part, socketName, CURRENT_STATE);
}

export async function clearSocket(socketName) {
  return clearSocketSelection(socketName, CURRENT_STATE);
}

export async function placeBySocketPath(socketPath, payload) {
  const state = CURRENT_STATE;
  if (!state || !socketPath) return null;

  const node = findSocketNodeFlexible(socketPath, state);
  const socketName = node?.name ?? getSocketNameFromPath(socketPath, state);
  if (!socketName) {
    debugWarn(state, "placeBySocketPath: socket not resolved", socketPath);
    return null;
  }

  knownSocketNames.add(socketName);

  const details = payload && typeof payload === "object" ? payload : null;
  const uri = details?.uri ?? details?.gltfUri ?? details?.gltf_uri;

  if (!uri) {
    removePartAtSocket(socketName, state);
    return null;
  }

  const attachNode = details?.attachNode ?? details?.attach_node ?? "Attach_Main";
  return placePartAtSocketInternal({ uri, attachNode }, socketName, state);
}

export async function hydrateFromServerAndRefresh() {
  await hydrateFromServer();
  await refreshBadges();
}

export function removeBySocketPath(socketPath) {
  const state = CURRENT_STATE;
  if (!state || !socketPath) return;

  const node = findSocketNodeFlexible(socketPath, state);
  const socketName = node?.name ?? getSocketNameFromPath(socketPath, state);
  if (!socketName) {
    debugWarn(state, "removeBySocketPath: socket not resolved", socketPath);
    return;
  }

  knownSocketNames.add(socketName);
  removePartAtSocket(socketName, state);
}

export function blinkSocketByPath(gltfNodePath) {
  if (!gltfNodePath || !CURRENT_STATE) return;

  const state = CURRENT_STATE;
  const { gizmosBySocket } = state;
  if (!gizmosBySocket || !gizmosBySocket.size) return;

  const path = String(gltfNodePath);
  const socketName =
    path.split("/").find(segment => segment && segment.startsWith("Socket_")) ||
    path;

  const entry = gizmosBySocket.get(socketName);
  if (!entry || !entry.group) return;

  const ring = new THREE.Mesh(
    new THREE.TorusGeometry(0.04, 0.004, 10, 28),
    new THREE.MeshBasicMaterial({ color: 0x33aaff, transparent: true, opacity: 0.9 })
  );
  ring.rotation.x = Math.PI / 2;
  entry.group.add(ring);

  setTimeout(() => {
    entry.group.remove(ring);
    ring.geometry?.dispose?.();
    if (ring.material) {
      if (Array.isArray(ring.material)) {
        for (const mat of ring.material) {
          mat?.dispose?.();
        }
      } else {
        ring.material.dispose?.();
      }
    }
  }, 800);
}

if (typeof window !== "undefined") {
  window.Engine3D = Object.assign(window.Engine3D || {}, {
    placeBySocketPath,
    removeBySocketPath,
    refreshBadges
  });
}
