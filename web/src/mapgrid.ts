// Фоновая сетка из точек (NR-035 п.2, NR-038 п.2): DOM-слой над
// канвой, шаг равен мелкой сетке привязки 20×20; плотность и смещение
// следуют масштабу и панораме карты, поэтому точки стоят на тех же
// координатах, куда привязываются узлы и точки изгиба. Видна, когда
// включены «Показывать сетку» и «Привязка к сетке»; точки
// ненавязчивые (контраст к фону ниже 1.5:1). При масштабе меньше
// 0.6 фон показывает только каждую пятую точку, чтобы не рябило
// (100 = 5×20 — кратен сетке, точки остаются на узлах сетки).
// Функции чистые — тестируются без cytoscape.

import type { Core } from 'cytoscape';
import { GRID_STEP } from './layout';

// Порог «редкой» сетки и кратность прореживания (NR-038 п.2):
// при zoom < GRID_RARE_ZOOM видна каждая пятая точка.
export const GRID_RARE_ZOOM = 0.6;
export const GRID_RARE_FACTOR = 5;

// GridPaint — CSS-свойства слоя сетки: размер тайла и смещение.
export interface GridPaint {
  sizeX: number;
  sizeY: number;
  posX: number;
  posY: number;
}

// gridPaint — тайл сетки в экранных пикселях: шаг привязки × масштаб
// (при zoom < 0.6 — каждая пятая точка: тайл 5×20); смещение —
// панорама (модельная точка (0,0) стоит в точке pan).
export function gridPaint(zoom: number, pan: { x: number; y: number }): GridPaint {
  const factor = zoom < GRID_RARE_ZOOM ? GRID_RARE_FACTOR : 1;
  const step = GRID_STEP * factor;
  return {
    sizeX: step * zoom,
    sizeY: step * zoom,
    posX: pan.x,
    posY: pan.y,
  };
}

// applyGridPaint — налить GridPaint в DOM-слой.
export function applyGridPaint(layer: HTMLElement, paint: GridPaint): void {
  layer.style.backgroundSize = `${paint.sizeX}px ${paint.sizeY}px`;
  layer.style.backgroundPosition = `${paint.posX}px ${paint.posY}px`;
}

// gridVisible — сетка показывается, когда включены оба
// переключателя: «Показывать сетку» и «Привязка к сетке».
export function gridVisible(showGrid: HTMLInputElement, snapGrid: HTMLInputElement): boolean {
  return showGrid.checked && snapGrid.checked;
}

// setupGridLayer — связывает слой #map-grid с картой: обновление на
// pan/zoom и на переключатели. Возвращает функцию принудительного
// обновления (для изменения переключателей).
export function setupGridLayer(cy: Core): () => void {
  const layer = document.getElementById('map-grid');
  if (layer === null) return () => undefined;
  const show = document.getElementById('show-grid') as HTMLInputElement | null;
  const snap = document.getElementById('snap-grid') as HTMLInputElement | null;
  const update = (): void => {
    const visible = show !== null && snap !== null && gridVisible(show, snap);
    layer.style.display = visible ? 'block' : 'none';
    applyGridPaint(layer, gridPaint(cy.zoom(), cy.pan()));
  };
  cy.on('pan zoom resize', update);
  update();
  return update;
}
