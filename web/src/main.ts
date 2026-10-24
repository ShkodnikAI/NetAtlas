// Точка входа интерфейса «Карта сети»: диалог токена (только память
// страницы), загрузка графа, правая панель, ручные действия.

import { ApiError, NetatlasApi, type DeviceInfo, type Graph, type LinkInfo, type NodeInfo } from './api';
import { setAuditBadge } from './audit';
import { renderComputerCard, renderComputers } from './computers';
import { renderDisks } from './disks';
import { createGraph, setGraph, type GraphCallbacks } from './graph';
import { fillEdit, fillNet, fillOverview, setObservations, type PanelHandlers } from './panels';
import {
  deviceRow,
  expectedStages,
  renderAlerts,
  renderProgress,
  setupScanScreen,
  startScan,
} from './scan';

const api = new NetatlasApi();

const $ = (id: string): HTMLElement => {
  const e = document.getElementById(id);
  if (e === null) throw new Error(`нет элемента #${id}`);
  return e;
};

const btn = (id: string): HTMLButtonElement => $(id) as HTMLButtonElement;

let graph: Graph = { nodes: [], links: [] };
let current: NodeInfo | null = null;
let currentLink: LinkInfo | null = null;
let selectedIds: string[] = [];
let connectMode = false;

const addKinds: [string, string][] = [
  ['internet', 'Интернет'],
  ['router', 'Роутер'],
  ['switch', 'Коммутатор'],
  ['ap', 'Точка доступа'],
  ['server', 'Сервер'],
  ['device', 'Компьютер'],
  ['laptop', 'Ноутбук'],
  ['printer', 'Принтер'],
  ['cloud', 'Неуправляемый коммутатор'],
  ['unknown', 'Неизвестное'],
];

// --- служебные ------------------------------------------------------------

function showNotice(message: string, isError: boolean): void {
  const n = $('notice');
  n.hidden = false;
  n.classList.toggle('error', isError);
  n.textContent = message;
}

function hideNotice(): void {
  $('notice').hidden = true;
}

async function reload(): Promise<void> {
  try {
    graph = await api.topology();
    setGraph(cy, graph);
    hideNotice();
    if (current !== null) {
      current = graph.nodes.find((n) => n.id === current?.id) ?? null;
      if (current !== null) void openPanel(current.id);
      else closePanel();
    }
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 401)) {
      showNotice(err instanceof Error ? err.message : 'Не удалось загрузить карту', true);
    }
  }
}

// --- граф -----------------------------------------------------------------

let currentLinkId: string | null = null;

const callbacks: GraphCallbacks = {
  onNodeSelect: (node) => {
    if (node === null) return;
    if (connectMode) {
      pushSelection(node.id);
      return;
    }
    current = node;
    currentLink = null;
    currentLinkId = null;
    btn('btn-disconnect').disabled = true;
    void openPanel(node.id);
  },
  onLinkSelect: (link, edgeId) => {
    if (link === null || edgeId === null) return;
    currentLink = link;
    currentLinkId = edgeId;
    current = null;
    btn('btn-disconnect').disabled = !link.manual;
    $('subtitle').textContent = link.manual
      ? 'Выбрана ручная связь — «Разорвать связь» активна'
      : 'Связь найдена сканером: разорвать её нельзя';
  },
};

const cy = createGraph($('graph'), callbacks);

function pushSelection(id: string): void {
  if (!selectedIds.includes(id)) selectedIds.push(id);
  cy.$('node').forEach((n) => {
    n.removeClass('selected');
  });
  for (const sid of selectedIds) cy.$id(sid).addClass('selected');
  updateConnectHint();
  if (selectedIds.length === 2) {
    void connectSelected();
  }
}

function updateConnectHint(): void {
  if (!connectMode) return;
  const names = selectedIds
    .map((id) => graph.nodes.find((n) => n.id === id)?.label ?? id)
    .join(' и ');
  showNotice(
    selectedIds.length === 0
      ? 'Выберите первый узел для соединения'
      : `Соединение: выбрано ${names} — выберите второй узел`,
    false,
  );
}

async function connectSelected(): Promise<void> {
  const [a, b] = selectedIds;
  if (a === undefined || b === undefined) return;
  try {
    await api.addLink(a, '', b, '');
    exitConnectMode();
    await reload();
  } catch (err) {
    showNotice(errMessage(err), true);
  }
}

function exitConnectMode(): void {
  connectMode = false;
  selectedIds = [];
  cy.$('node').removeClass('selected');
  btn('btn-connect').disabled = false;
  hideNotice();
  $('subtitle').textContent = 'Нажмите на значок устройства, чтобы открыть вкладку с подробностями';
}

// --- панель ----------------------------------------------------------------

function closePanel(): void {
  $('panel').classList.remove('open');
  current = null;
  btn('btn-disconnect').disabled = true;
}

async function openPanel(id: string): Promise<void> {
  try {
    const info: DeviceInfo = await api.device(id);
    const kind = graph.nodes.find((n) => n.id === id)?.kind ?? 'unknown';
    const panel = $('panel');
    panel.classList.add('open');
    const title = $('panel-title');
    title.textContent = info.hostname !== '' ? info.hostname : info.id;

    fillOverview($('page-overview'), info, kind);

    const handlers: PanelHandlers = {
      onRename: async (nid, name) => {
        try {
          await api.updateDevice(nid, { name });
          await reload();
        } catch (err) {
          showNotice(errMessage(err), true);
        }
      },
      onClass: async (nid, klass) => {
        try {
          await api.updateDevice(nid, { class: klass });
          await reload();
        } catch (err) {
          showNotice(errMessage(err), true);
        }
      },
      onVerify: async (nid) => {
        const verdict = panel.querySelector('.verdict');
        try {
          const report = await api.verify(nid);
          if (verdict !== null) {
            const alive = report.results.filter((r) => r.alive).length;
            verdict.className = `verdict ${report.verified ? 'ok' : 'bad'}`;
            verdict.textContent = report.verified
              ? `Живых адресов: ${alive} из ${report.results.length} — устройство проверено`
              : `Ответов нет: 0 из ${report.results.length}`;
          }
          await reload();
        } catch (err) {
          if (verdict !== null) {
            verdict.className = 'verdict bad';
            verdict.textContent = errMessage(err);
          }
        }
      },
      onDelete: async (nid) => {
        try {
          await api.deleteDevice(nid);
          closePanel();
          await reload();
        } catch (err) {
          showNotice(errMessage(err), true);
        }
      },
    };
    fillEdit($('page-edit'), info, handlers);

    setObservations(info.observations);
    const netPage = $('page-net');
    fillNet(netPage, id, graph);
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 401)) {
      showNotice(errMessage(err), true);
    }
  }
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'Неизвестная ошибка';
}

// --- вкладки ---------------------------------------------------------------

const tabs: [string, string][] = [
  ['tab-overview', 'page-overview'],
  ['tab-disks', 'page-disks'],
  ['tab-user', 'page-user'],
  ['tab-net', 'page-net'],
  ['tab-edit', 'page-edit'],
];

function selectTab(tabId: string): void {
  for (const [tab, page] of tabs) {
    const tabEl = $(tab);
    const isSel = tab === tabId;
    tabEl.setAttribute('aria-selected', isSel ? 'true' : 'false');
    $(page).classList.toggle('active', isSel);
  }
}

// --- диалоги ---------------------------------------------------------------

function setupTokenDialog(): void {
  const dialog = $('token-dialog') as HTMLDialogElement;
  dialog.showModal();
  $('token-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const input = $('token-input') as HTMLInputElement;
    api.setToken(input.value);
    input.value = '';
    $('token-help').hidden = true;
    dialog.close();
    void reload();
  });
}

function askToken(): void {
  $('token-help').hidden = false;
  ($('token-dialog') as HTMLDialogElement).showModal();
}

function setupAddDialog(): void {
  const select = $('add-kind') as HTMLSelectElement;
  for (const [value, label] of addKinds) {
    const opt = document.createElement('option');
    opt.value = value;
    opt.textContent = label;
    select.append(opt);
  }
  const dialog = $('add-dialog') as HTMLDialogElement;
  $('btn-add').addEventListener('click', () => {
    ($('add-error') as HTMLElement).hidden = true;
    dialog.showModal();
  });
  (dialog.querySelector('.cancel') as HTMLButtonElement).addEventListener('click', () => dialog.close());
  $('add-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const nameInput = $('add-name') as HTMLInputElement;
    try {
      await api.addDevice(select.value, nameInput.value);
      dialog.close();
      nameInput.value = '';
      await reload();
    } catch (err) {
      const box = $('add-error') as HTMLElement;
      box.hidden = false;
      box.textContent = errMessage(err);
    }
  });
}

// --- запуск ----------------------------------------------------------------

api.onUnauthorized = () => askToken();

// --- экраны ----------------------------------------------------------------

type ScreenName = 'map' | 'scan' | 'devices' | 'computers' | 'disks';

let openComputerId: string | null = null;

function showScreen(name: ScreenName): void {
  $('screen-scan').hidden = name !== 'scan';
  $('screen-devices').hidden = name !== 'devices';
  $('screen-computers').hidden = name !== 'computers';
  $('screen-disks').hidden = name !== 'disks';
  (document.querySelector('.workspace') as HTMLElement).hidden = name !== 'map';
  document.querySelectorAll('nav .item[data-page]').forEach((item) => {
    const on = (item as HTMLElement).dataset.page === name;
    item.classList.toggle('active', on);
    if (on) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });
  if (name === 'scan') void initScanScreen();
  if (name === 'devices') void initDevicesScreen();
  if (name === 'computers') void initComputersScreen();
  if (name === 'disks') void initDisksScreen();
  if (name === 'map') void reload();
}

// --- компьютеры и диски (NR-009) -------------------------------------------

async function initComputersScreen(): Promise<void> {
  const root = $('computers-root');
  try {
    const { computers } = await api.computers();
    if (openComputerId !== null) {
      const id = openComputerId;
      const card = await api.computer(id);
      renderComputerCard(root, card, () => {
        openComputerId = null;
        void initComputersScreen();
      });
    } else {
      renderComputers(root, computers, (id) => {
        openComputerId = id;
        void initComputersScreen();
      });
    }
  } catch (err) {
    renderComputers(root, [], () => undefined);
    showNotice(err instanceof Error ? err.message : 'ошибка загрузки компьютеров', true);
  }
}

async function initDisksScreen(): Promise<void> {
  const root = $('disks-root');
  try {
    const { disks } = await api.disks();
    renderDisks(root, disks);
  } catch (err) {
    renderDisks(root, []);
    showNotice(err instanceof Error ? err.message : 'ошибка загрузки дисков', true);
  }
}

document.querySelectorAll('nav .item[data-page]').forEach((item) => {
  item.addEventListener('click', () => showScreen((item as HTMLElement).dataset.page as ScreenName));
});

// --- мастер сканирования ---------------------------------------------------

const scanEls = {
  subnets: $('scan-subnets'),
  ping: $('scan-ping') as HTMLInputElement,
  names: $('scan-names') as HTMLInputElement,
  snmp: $('scan-snmp') as HTMLInputElement,
  snmpNote: $('scan-snmp-note'),
  leasesPath: $('scan-leases-path') as HTMLInputElement,
  leasesFormat: $('scan-leases-format') as HTMLSelectElement,
  run: $('scan-run') as HTMLButtonElement,
  error: $('scan-error'),
  progressWrap: $('scan-progress-wrap'),
  progress: $('scan-progress'),
  status: $('scan-status'),
  alertsList: $('alerts-list'),
  tableBody: document.querySelector('#devices-table tbody') as HTMLElement,
  badge: $('alerts-badge'),
};

let scanCfg: { subnets: string[]; snmp: boolean; audit_ok: boolean } = {
  subnets: [], snmp: false, audit_ok: true,
};

async function initScanScreen(): Promise<void> {
  try {
    scanCfg = await api.config();
    setAuditBadge($('audit-badge'), scanCfg.audit_ok);
    setupScanScreen(scanCfg, scanEls);
  } catch (err) {
    scanEls.error.hidden = false;
    scanEls.error.textContent = errMessage(err);
  }
}

scanEls.run.addEventListener('click', async () => {
  scanEls.error.hidden = true;
  const body = startScan(scanEls);
  if (body.subnets.length === 0) {
    scanEls.error.hidden = false;
    scanEls.error.textContent = 'Выберите хотя бы одну подсеть.';
    return;
  }
  scanEls.run.disabled = true;
  try {
    const started = await api.startScan(body);
    const expected = expectedStages(
      body.ping,
      body.names,
      body.snmp_targets.length > 0,
      body.leases_path !== undefined,
    );
    const poll = window.setInterval(async () => {
      try {
        const view = await api.scanState(started.id);
        renderProgress(scanEls, view, expected);
        if (view.status !== 'running') {
          window.clearInterval(poll);
          scanEls.run.disabled = false;
        }
      } catch {
        window.clearInterval(poll);
        scanEls.run.disabled = false;
      }
    }, 1000);
  } catch (err) {
    scanEls.error.hidden = false;
    scanEls.error.textContent = errMessage(err);
    scanEls.run.disabled = false;
  }
});

// --- найденные устройства --------------------------------------------------

async function initDevicesScreen(): Promise<void> {
  try {
    const [devs, alerts] = await Promise.all([api.devices(), api.alerts()]);
    scanEls.tableBody.textContent = '';
    for (const d of devs.devices) {
      scanEls.tableBody.append(deviceRow(d, async (id, klass) => {
        try {
          await api.updateDevice(id, { class: klass });
          await initDevicesScreen();
        } catch (err) {
          showNotice(errMessage(err), true);
        }
      }));
    }
    renderAlerts(scanEls, alerts.alerts, async (id) => {
      try {
        await api.ackAlert(id);
        await initDevicesScreen();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    });
  } catch (err) {
    showNotice(errMessage(err), true);
  }
}

// Обновить бейдж оповещений при старте и после сканов.
async function refreshAlertBadge(): Promise<void> {
  try {
    const alerts = await api.alerts();
    renderAlerts(scanEls, alerts.alerts, async (id) => {
      await api.ackAlert(id);
      await refreshAlertBadge();
    });
  } catch {
    // бейдж не критичен
  }
}

// Плашка аудита при старте: состояние приходит из /api/config;
// при недоступности сервера плашка скрыта (нет данных — нет тревоги).
async function refreshAuditBadge(): Promise<void> {
  try {
    const cfg = await api.config();
    setAuditBadge($('audit-badge'), cfg.audit_ok);
  } catch {
    // плашка не критична
  }
}

$('panel-close').addEventListener('click', closePanel);
$('btn-reload').addEventListener('click', () => void reload());

$('btn-connect').addEventListener('click', () => {
  if (connectMode) {
    exitConnectMode();
    return;
  }
  connectMode = true;
  selectedIds = [];
  btn('btn-connect').disabled = true;
  updateConnectHint();
});

$('btn-disconnect').addEventListener('click', async () => {
  if (currentLink === null || currentLinkId === null) return;
  try {
    await api.deleteLink(currentLinkId);
    currentLink = null;
    currentLinkId = null;
    btn('btn-disconnect').disabled = true;
    await reload();
  } catch (err) {
    showNotice(errMessage(err), true);
  }
});

// Клавиатура: Esc закрывает панель и режим соединения; вкладки
// переключаются стрелками.
document.addEventListener('keydown', (ev) => {
  if (ev.key === 'Escape') {
    if (($('add-dialog') as HTMLDialogElement).open) return;
    if (($('token-dialog') as HTMLDialogElement).open) return;
    closePanel();
    if (connectMode) exitConnectMode();
  }
});

for (let i = 0; i < tabs.length; i++) {
  const [tabId] = tabs[i] ?? ['', ''];
  if (tabId === '') continue;
  $(tabId).addEventListener('click', () => selectTab(tabId));
  $(tabId).addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft') return;
    const idx = tabs.findIndex(([t]) => t === tabId);
    if (idx < 0) return;
    const next = ev.key === 'ArrowRight' ? (idx + 1) % tabs.length : (idx + tabs.length - 1) % tabs.length;
    const [nextTab] = tabs[next] ?? ['', ''];
    if (nextTab !== '') {
      selectTab(nextTab);
      ($(nextTab) as HTMLButtonElement).focus();
    }
  });
}

setupTokenDialog();
setupAddDialog();
void refreshAlertBadge();
void refreshAuditBadge();
