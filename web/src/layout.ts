// Раскладка карты без пересечения подписей (NR-031 п.4): оценка
// габаритов подписи, сетка для узлов без связей с шагом по ширине
// подписи, разведение пересечений. Функции чистые — тестируются без
// cytoscape (vitest), graph.ts применяет их к позициям узлов.

// Габариты узла cytoscape совпадают со style из nodes.ts.
export const NODE_SIZE = { width: 44, height: 34 } as const;

// Подпись: text-max-width в стиле графа (px), высота строки при
// font-size 11.
export const LABEL_MAX_WIDTH = 140;
export const LABEL_LINE_HEIGHT = 14;
// Знаков в строке при font-size 11 (system-ui) — оценка ширины.
const CHAR_WIDTH = 6.4;
// Зазор между узлом и подписью (text-margin-y).
export const LABEL_GAP = 6;
// Минимальный зазор между габаритами разных узлов.
export const NODE_GAP = 18;
// Шаг сетки для узлов без связей: ширина подписи + поля.
export const GRID_STEP_X = LABEL_MAX_WIDTH + 60;
export const GRID_STEP_Y = NODE_SIZE.height + LABEL_GAP + LABEL_LINE_HEIGHT + 66;
// Колонок в сетке одиночных узлов.
export const GRID_COLUMNS = 5;

// LabelSize — оценка габаритов подписи после переноса по ширине.
export interface LabelSize {
  width: number;
  height: number;
}

// measureLabel — ширина и высота подписи с учётом переноса:
// каждая строка (по \n) не ширине LABEL_MAX_WIDTH, высота — строки ×
// высота строки.
export function measureLabel(text: string): LabelSize {
  const lines = text.split('\n');
  let linesCount = 0;
  let widest = 0;
  for (const line of lines) {
    const width = Math.min(LABEL_MAX_WIDTH, line.length * CHAR_WIDTH + 4);
    widest = Math.max(widest, width);
    linesCount += Math.max(1, Math.ceil((line.length * CHAR_WIDTH + 4) / LABEL_MAX_WIDTH));
  }
  if (linesCount === 0) linesCount = 1;
  return { width: widest, height: linesCount * LABEL_LINE_HEIGHT };
}

// Box — габаритный прямоугольник узла с подписью в модельных
// координатах.
export interface Box {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

// boxOf — габарит узла и подписи вокруг центра (x, y): узел, зазор,
// под ним подпись (text-valign: bottom).
export function boxOf(x: number, y: number, label: LabelSize): Box {
  const labelH = label.height + LABEL_GAP;
  const halfW = Math.max(NODE_SIZE.width, label.width) / 2;
  return {
    x1: x - halfW,
    y1: y - NODE_SIZE.height / 2,
    x2: x + halfW,
    y2: y + NODE_SIZE.height / 2 + labelH,
  };
}

function expanded(b: Box, gap: number): Box {
  return { x1: b.x1 - gap, y1: b.y1 - gap, x2: b.x2 + gap, y2: b.y2 + gap };
}

// overlapArea — величина пересечения двух прямоугольников (0 если
// не пересекаются).
export function overlapArea(a: Box, b: Box): number {
  const ox = Math.min(a.x2, b.x2) - Math.max(a.x1, b.x1);
  const oy = Math.min(a.y2, b.y2) - Math.max(a.y1, b.y1);
  if (ox <= 0 || oy <= 0) return 0;
  return ox * oy;
}

// GridPlacement — шаг сетки и прямоугольник, в котором одиночные
// узлы не задевают связанный компонент.
export interface GridPlacement {
  originX: number;
  originY: number;
  stepX: number;
  stepY: number;
}

// gridPlacement — сетка справа от связанной части графа (или от
// нуля, если связанной части нет): шаг учитывает ширину подписи.
export function gridPlacement(connected: Box | null): GridPlacement {
  if (connected === null) {
    return { originX: 0, originY: 0, stepX: GRID_STEP_X, stepY: GRID_STEP_Y };
  }
  return {
    originX: connected.x2 + 160,
    originY: connected.y1,
    stepX: GRID_STEP_X,
    stepY: GRID_STEP_Y,
  };
}

export interface Positioned {
  id: string;
  x: number;
  y: number;
  label: LabelSize;
}

// gridPositions — позиции одиночных узлов: по сетке слева направо,
// сверху вниз, порядок входа сохраняется.
export function gridPositions(
  ids: string[],
  placement: GridPlacement,
): Map<string, { x: number; y: number }> {
  const out = new Map<string, { x: number; y: number }>();
  for (let i = 0; i < ids.length; i++) {
    const id = ids[i] ?? '';
    const col = i % GRID_COLUMNS;
    const row = Math.floor(i / GRID_COLUMNS);
    out.set(id, {
      x: placement.originX + col * placement.stepX,
      y: placement.originY + row * placement.stepY,
    });
  }
  return out;
}

// deoverlap — разводит узлы, чьи габариты (узел + подпись + зазор)
// пересекаются: пара сдвигается вдоль оси наименьшего проникновения.
// Детерминированно: порядок обхода фиксирован, до MAX_ROUNDS ходов.
export function deoverlap(nodes: Positioned[]): void {
  const MAX_ROUNDS = 120;
  for (let round = 0; round < MAX_ROUNDS; round++) {
    let moved = false;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i] as Positioned;
        const b = nodes[j] as Positioned;
        const ba = expanded(boxOf(a.x, a.y, a.label), NODE_GAP);
        const bb = expanded(boxOf(b.x, b.y, b.label), NODE_GAP);
        const ox = Math.min(ba.x2, bb.x2) - Math.max(ba.x1, bb.x1);
        const oy = Math.min(ba.y2, bb.y2) - Math.max(ba.y1, bb.y1);
        if (ox <= 0 || oy <= 0) continue;
        if (ox <= oy) {
          const dir = a.x <= b.x ? -1 : 1;
          a.x += (dir * ox) / 2;
          b.x -= (dir * ox) / 2;
        } else {
          const dir = a.y <= b.y ? -1 : 1;
          a.y += (dir * oy) / 2;
          b.y -= (dir * oy) / 2;
        }
        moved = true;
      }
    }
    if (!moved) break;
  }
}

// anyOverlap — остались ли пересечения (самопроверка раскладки).
export function anyOverlap(nodes: Positioned[]): boolean {
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i] as Positioned;
      const b = nodes[j] as Positioned;
      if (overlapArea(boxOf(a.x, a.y, a.label), boxOf(b.x, b.y, b.label)) > 0) return true;
    }
  }
  return false;
}
