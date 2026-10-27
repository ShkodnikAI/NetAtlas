// Фоновая сетка из точек (NR-035 п.2): DOM-слой над канвой, шаг
// равен шагу привязки; плотность и смещение следуют масштабу и
// панораме карты, поэтому точки стоят на тех же координатах, куда
// привязываются узлы. Видна, когда включены «Показывать сетку» и
// «Привязка к сетке»; точки ненавязчивые (контраст к фону ниже
// 1.5:1). Функции чистые — тестируются без cytoscape.

import type { Core } from 'cytoscape';
import { SNAP_STEP_X, SNAP_STEP_Y } from './layout';

// GridPaint — CSS-свойства слоя сетки: размер тайла и смещение.
export interface GridPaint {
  sizeX: number;
  sizeY: number;
  posX: number;
  posY: number;
}

// gridPaint — тайл сетки в экранных пикселях: шаг привязки × масштаб;
// смещение — панорама (модельная точка (0,0) стоит в точке pan).
export function gridPaint(zoom: number, pan: { x: number; y: number }): GridPaint {
  return {
    sizeX: SNAP_STEP_X * zoom,
    sizeY: SNAP_STEP_Y * zoom,
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
