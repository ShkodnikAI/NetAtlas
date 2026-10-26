// Точка входа интерфейса «Карта сети»: диалог токена (только память
// страницы), загрузка графа, правая панель, ручные действия.

import { ApiError, NetatlasApi, type DeviceInfo, type Graph, type LinkInfo, type NodeInfo } from './api';
import { setAuditBadge } from './audit';
import { renderComputerCard, renderComputers } from './computers';
import { renderActivity, validateEnableInput } from './activity';
import { renderReports, validateAnswerText, validateDraftInput } from './reports';
import {
  renderDraftForm,
  renderScriptAudit,
  renderScriptList,
  renderStages,
  renderVersionCard,
  validateSignInput,
  type ScriptHandlers,
} from './scripts';
import { renderDisks } from './disks';
import { renderQuality } from './quality';
import { renderSecurity } from './security';
import { createGraph, setGraph, type GraphCallbacks } from './graph';
import { renderLegend } from './legend';
import { fillEdit, fillNet, fillOverview, setObservations, type PanelHandlers } from './panels';
import {
  renderDevicesTable,
  expectedStages,
  renderAlerts,
  renderProgress,
  setupScanScreen,
  startScan,
} from './scan';

let scriptsSelected: number | null = null;

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
// savedPositions — узлы, сдвинутые владельцем (NR-032 п.4):
// детерминированная раскладка их не трогает; кнопка «Выстроить
// сеткой» очищает набор (и на сервере).
let savedPositions = new Set<string>();

const addKinds: [string, string][] = [
  ['internet', 'Интернет'],
  ['router', 'Роутер'],
  ['switch', 'Коммутатор'],
  ['ap', 'Точка доступа'],
  ['server', 'Сервер'],
  ['device', 'Компьютер'],
  ['laptop', 'Ноутбук'],
  ['printer', 'Принтер'],
  ['phone', 'Телефон'],
  ['iot', 'IoT-устройство'],
  ['tv', 'Телевизор'],
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
    // Позиции владельца (NR-032 п.4): сервер помнит сдвинутые узлы.
    try {
      const { positions } = await api.positions();
      savedPositions = new Set(positions.map((p) => p.id));
    } catch {
      // без позиций — вся карта сеткой
    }
    setGraph(cy, graph, savedPositions);
    renderLegend($('map-legend'), graph);
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

// Перетаскивание узла запоминается на сервере (NR-032 п.4): позиция
// переживёт перезагрузку страницы и не будет тронута раскладкой.
cy.on('dragfree', 'node', (ev) => {
  const n = ev.target;
  savedPositions.add(n.id());
  void api.savePosition(n.id(), n.position('x'), n.position('y')).catch(() => {
    // позиция косметическая: ошибка сети не роняет интерфейс
  });
});

// «Выстроить сеткой» (NR-032 п.4): очистить сохранённые позиции и
// заново выстроить карту детерминированной сеткой.
$('btn-arrange').addEventListener('click', async () => {
  try {
    await api.clearPositions();
  } catch {
    // даже при ошибке сети выстроим локально
  }
  savedPositions = new Set<string>();
  setGraph(cy, graph, savedPositions);
  renderLegend($('map-legend'), graph);
});

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

    fillOverview($('page-overview'), info, kind, () => selectTab('tab-edit'));

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
      // Ручной тип (NR-032 п.1) перекрывает автоматический вывод.
      onKind: async (nid, newKind) => {
        try {
          await api.updateDevice(nid, { kind: newKind });
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

// Была ли уже попытка входа с токеном: фоновые 401 при старте
// открывают диалог, но сообщение об ошибке в нём показываем только
// после реальной неудачной попытки (NR-031 п.6: сообщение — только
// когда оно есть).
let tokenAttempted = false;

function setupTokenDialog(): void {
  const dialog = $('token-dialog') as HTMLDialogElement;
  dialog.showModal();
  $('token-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    tokenAttempted = true;
    const input = $('token-input') as HTMLInputElement;
    api.setToken(input.value);
    input.value = '';
    $('token-help').hidden = true;
    dialog.close();
    void reload();
    // NR-031 п.2: после успешного входа подсети мастера и плашка
    // аудита обновляются без повторного захода на экран.
    void loadScanConfig();
  });
}

function askToken(): void {
  $('token-help').hidden = !tokenAttempted;
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

type ScreenName = 'map' | 'scan' | 'devices' | 'computers' | 'disks' | 'quality' | 'security' | 'scripts' | 'activity' | 'reports';

let openComputerId: string | null = null;

function showScreen(name: ScreenName): void {
  $('screen-scan').hidden = name !== 'scan';
  $('screen-devices').hidden = name !== 'devices';
  $('screen-computers').hidden = name !== 'computers';
  $('screen-disks').hidden = name !== 'disks';
  $('screen-quality').hidden = name !== 'quality';
  $('screen-security').hidden = name !== 'security';
  $('screen-scripts').hidden = name !== 'scripts';
  $('screen-activity').hidden = name !== 'activity';
  $('screen-reports').hidden = name !== 'reports';
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
  if (name === 'quality') void initQualityScreen();
  if (name === 'security') void initSecurityScreen();
  if (name === 'scripts') void initScriptsScreen();
  if (name === 'activity') void initActivityScreen();
  if (name === 'reports') void initReportsScreen();
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

async function initQualityScreen(): Promise<void> {
  const root = $('screen-quality');
  try {
    const [matrix, bottlenecks, series] = await Promise.all([
      api.qualityMatrix(),
      api.qualityBottlenecks(),
      api.qualitySeries('speed'),
    ]);
    renderQuality(root, matrix.matrix, bottlenecks.bottlenecks, series.series);
  } catch (err) {
    showNotice(err instanceof Error ? err.message : 'ошибка загрузки качества', true);
  }
}

// --- безопасность (NR-010) --------------------------------------------------

let securityCardId: string | null = null;

async function initSecurityScreen(): Promise<void> {
  const root = $('screen-security');
  const holder = $('security-root');
  try {
    const summary = await api.securitySummary();
    let card = null;
    if (securityCardId !== null) {
      try {
        card = await api.securityComputer(securityCardId);
      } catch {
        card = null;
      }
    }
    renderSecurity(holder, summary, card, {
      root,
      onComputer: (id: string) => {
        securityCardId = id === '' ? null : id;
        void initSecurityScreen();
      },
    });
  } catch (err) {
    renderSecurity(holder, {
      score: null, generated_at: '', counts: {}, unknown_checks: 0,
      computers: [], findings: [], network: [],
    }, null, { root, onComputer: () => undefined });
    showNotice(err instanceof Error ? err.message : 'ошибка загрузки безопасности', true);
  }
}

// --- скрипты и тесты (NR-011) ----------------------------------------------

async function initScriptsScreen(): Promise<void> {
  const listRoot = $('scripts-list');
  const cardRoot = $('scripts-card');
  const stagesRoot = $('scripts-stages');
  const auditRoot = $('scripts-audit');
  const draftRoot = $('scripts-draft');
  try {
    const [list, catalog, jobs, audit] = await Promise.all([
      api.scripts(),
      api.catalog(),
      api.jobs(),
      api.auditList(200),
    ]);
    renderStages(stagesRoot, list.stages);
    renderScriptAudit(auditRoot, audit.entries);

    const versionsByScript: Record<number, import('./api').VersionRow | undefined> = {};
    for (const v of list.versions) versionsByScript[v.script_id] = v;
    if (scriptsSelected === null && list.scripts.length > 0) scriptsSelected = list.scripts[0]?.id ?? null;
    renderScriptList(listRoot, list.scripts, versionsByScript, scriptsSelected, (id) => {
      scriptsSelected = id;
      void initScriptsScreen();
    });

    const handlers = handlersFor();

    renderDraftForm(draftRoot, catalog.templates, handlers);

    const script = list.scripts.find((s) => s.id === scriptsSelected);
    const version = script === undefined ? undefined : versionsByScript[script.id];
    if (script === undefined || version === undefined) {
      cardRoot.textContent = '';
      cardRoot.append(Object.assign(document.createElement('p'), { className: 'muted', textContent: 'Выберите скрипт слева.' }));
      return;
    }
    const card = await api.scriptCard(script.id);
    renderVersionCard(cardRoot, script, version, card.checks[version.id] ?? [], card.signatures[version.id], jobs.jobs, handlers);
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 401)) {
      showNotice(errMessage(err), true);
    }
  }
}

function handlersFor(): ScriptHandlers {
  return {
    onSelect: (id) => {
      scriptsSelected = id;
      void initScriptsScreen();
    },
    onCreateDraft: async (body) => {
      try {
        await api.createScript(body);
        await initScriptsScreen();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onStatus: async (sid, vid, to, comment) => {
      try {
        await api.setScriptStatus(sid, vid, to, comment);
        await initScriptsScreen();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onSign: (sid, vid, name, sha) => {
      // Подтверждение вводом имени и хэша: подписывается то, что на экране.
      const dlgName = window.prompt(`Подпись. Введите имя скрипта целиком («${name}»):`);
      if (dlgName === null) return;
      const dlgSha = window.prompt('Введите хэш содержимого (скопируйте из карточки):');
      if (dlgSha === null) return;
      const problem = validateSignInput(dlgName, name, dlgSha, sha);
      if (problem !== '') {
        showNotice(problem, true);
        return;
      }
      void (async () => {
        try {
          await api.sign(sid, vid, dlgName, dlgSha.trim().toLowerCase());
          await initScriptsScreen();
        } catch (err) {
          showNotice(errMessage(err), true);
        }
      })();
    },
    onCheckRun: async (sid, vid) => {
      try {
        const res = await api.checkRun(sid, vid);
        showNotice(
          res.report.ok ? 'Статические проверки пройдены: статус «Проверка кода».' : 'Статические проверки нашли ошибки уровня Error.',
          !res.report.ok,
        );
        await initScriptsScreen();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onCheckResult: async (sid, vid, body) => {
      try {
        await api.checkResult(sid, vid, body);
        await initScriptsScreen();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onViewCode: async (sid, vid) => {
      try {
        const v = await api.scriptVersion(sid, vid);
        window.alert(v.content);
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onCreateJob: async (body) => {
      try {
        await api.createJob(body);
        await initScriptsScreen();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onStopJob: async (jobId) => {
      try {
        await api.stopJob(jobId);
        await initScriptsScreen();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
  };
}

// --- активность (NR-012) ---------------------------------------------------

async function initActivityScreen(): Promise<void> {
  const root = $('activity-root');
  const handlers = {
    onEnable: async (agentID: string, confirmation: string) => {
      const problem = validateEnableInput(agentID, confirmation);
      if (problem !== '') {
        showNotice(problem, true);
        return;
      }
      try {
        await api.activityEnable(agentID, confirmation);
        showNotice('Сбор включён: подтверждение записано в аудит. Значок появится у сотрудников.', false);
        await initActivityScreen();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onDisable: async (agentID: string) => {
      try {
        await api.activityDisable(agentID);
        await initActivityScreen();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onPurge: async (agentID: string) => {
      try {
        const res = await api.activityPurge(agentID);
        showNotice(`Удалено записей: ${res.rows}`, false);
        await initActivityScreen();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onLoad: async () => {
      await initActivityScreen();
    },
  };
  try {
    const [computers, summary] = await Promise.all([
      api.activityComputers(),
      api.activitySummary('?from=' + encodeURIComponent(new Date(Date.now() - 24 * 3600e3).toISOString())),
    ]);
    renderActivity({ root, onRefresh: () => void initActivityScreen() }, summary, computers.computers, handlers);
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 401)) {
      showNotice(errMessage(err), true);
    }
  }
}

// --- отчёты для ИИ (NR-013) ------------------------------------------------

async function initReportsScreen(): Promise<void> {
  const root = $('reports-root');
  let list: Awaited<ReturnType<typeof api.reports>>['reports'] = [];
  let current: Awaited<ReturnType<typeof api.report>> | null = null;
  let mapping: Awaited<ReturnType<typeof api.reportMapping>>['mapping'] | null = null;

  const show = (): void => {
    renderReports({ root, onRefresh: () => void initReportsScreen() }, list, current, mapping, handlers);
  };

  const handlers = {
    onCreate: async (topic: string, agentID: string, question: string) => {
      try {
        const res = await api.createReport(topic, agentID, question);
        showNotice(
          res.warnings.length > 0
            ? `Отчёт №${res.id} создан. Внимание: ${res.warnings.join('; ')}`
            : `Отчёт №${res.id} создан: текст очищен, проверьте перед отправкой.`,
          res.warnings.length > 0,
        );
        await initReportsScreen();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onOpen: async (id: number) => {
      try {
        current = await api.report(id);
        mapping = null;
        show();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onCopy: (text: string) => {
      void navigator.clipboard
        .writeText(text)
        .then(() => showNotice('Очищенный текст скопирован: вставьте его в диалог с ИИ вручную.', false))
        .catch(() => showNotice('Браузер не дал доступ к буферу обмена — выделите текст вручную.', true));
    },
    onAnswer: async (id: number, text: string) => {
      const problem = validateAnswerText(text);
      if (problem !== '') {
        showNotice(problem, true);
        return;
      }
      try {
        await api.reportAnswer(id, text);
        showNotice('Ответ принят как предложение. Из него можно создать черновик.', false);
        current = await api.report(id);
        show();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onAskAI: async (id: number) => {
      try {
        const res = await api.reportAskAI(id);
        showNotice('Модель ответила: ответ сохранён как предложение.', false);
        void res;
        current = await api.report(id);
        show();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onDraft: async (id: number, name: string, fragment: string) => {
      const problem = validateDraftInput(name, fragment);
      if (problem !== '') {
        showNotice(problem, true);
        return;
      }
      try {
        const res = await api.reportDraft(id, name, fragment);
        showNotice(`Черновик создан: скрипт №${res.script_id}, версия №${res.version_id} (draft). Путь дальше — конвейер скриптов.`, false);
        current = await api.report(id);
        show();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
    onMapping: async (id: number) => {
      try {
        mapping = (await api.reportMapping(id)).mapping;
        show();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    },
  };

  try {
    list = (await api.reports()).reports;
    show();
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 401)) {
      showNotice(errMessage(err), true);
    }
  }
}

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

const scanCfgEls = {
  cfgError: $('scan-config-error'),
  retry: $('scan-retry') as HTMLButtonElement,
  runHint: $('scan-run-hint'),
};

let scanCfg: { subnets: string[]; snmp: boolean; audit_ok: boolean } | null = null;

// updateRunState — кнопка «Запустить сканирование» отключена, пока
// нет подсетей, с подсказкой почему (NR-031 п.2).
function updateRunState(): void {
  const boxes = scanEls.subnets.querySelectorAll('input[type="checkbox"]');
  const checked = scanEls.subnets.querySelectorAll('input[type="checkbox"]:checked');
  let disabled = true;
  let hint = '';
  if (scanCfg === null) {
    hint = 'Настройки сервера не загружены — сканирование недоступно.';
  } else if (boxes.length === 0) {
    hint = 'На сервере не заданы подсети (--subnets): сканировать нечего.';
  } else if (checked.length === 0) {
    hint = 'Выберите хотя бы одну подсеть.';
  } else {
    disabled = false;
  }
  scanEls.run.disabled = disabled;
  scanCfgEls.runHint.textContent = hint;
}

// loadScanConfig — подсети грузятся после успешного входа и при
// каждом открытии мастера; при ошибке — видимое сообщение и
// «Повторить» (NR-031 п.2). 401 не показываем: диалог токена
// открывается сам.
async function loadScanConfig(): Promise<void> {
  try {
    const cfg = await api.config();
    scanCfg = cfg;
    setAuditBadge($('audit-badge'), cfg.audit_ok);
    scanCfgEls.cfgError.hidden = true;
    scanCfgEls.retry.hidden = true;
    await setupScanScreen(cfg, scanEls);
    updateRunState();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return;
    scanCfg = null;
    scanEls.subnets.textContent = '';
    scanCfgEls.cfgError.hidden = false;
    scanCfgEls.cfgError.textContent =
      'Не удалось загрузить настройки сервера: ' + errMessage(err);
    scanCfgEls.retry.hidden = false;
    updateRunState();
  }
}

async function initScanScreen(): Promise<void> {
  await loadScanConfig();
}

scanEls.subnets.addEventListener('change', () => updateRunState());
scanCfgEls.retry.addEventListener('click', () => void loadScanConfig());

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
          updateRunState();
          // NR-031 п.8: после завершения скана таблица и карта
          // обновляются сами.
          if (view.status === 'done') {
            void reload();
            void initDevicesScreen();
            void refreshAlertBadge();
          }
        }
      } catch {
        window.clearInterval(poll);
        scanEls.run.disabled = false;
        updateRunState();
      }
    }, 1000);
  } catch (err) {
    scanEls.error.hidden = false;
    scanEls.error.textContent = errMessage(err);
    scanEls.run.disabled = false;
    updateRunState();
  }
});

// --- найденные устройства --------------------------------------------------

async function initDevicesScreen(): Promise<void> {
  try {
    const [devs, alerts] = await Promise.all([api.devices(), api.alerts()]);
    renderDevicesTable(scanEls.tableBody, devs.devices, async (id, klass) => {
      try {
        await api.updateDevice(id, { class: klass });
        await initDevicesScreen();
      } catch (err) {
        showNotice(errMessage(err), true);
      }
    });
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

// Доступ к инстансу cytoscape для сквозных тестов интерфейса
// (Playwright, NR-031): данные уже отрисованы на странице, хук даёт
// только доступ к API карты для проверки раскладки.
(window as unknown as { __netatlas?: { cy: unknown } }).__netatlas = { cy };
