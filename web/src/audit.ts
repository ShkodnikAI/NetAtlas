// Плашка целостности журнала аудита (NR-023): красная полоса в левой
// панели, когда цепочка хэшей нарушена. Состояние приходит с сервера
// в /api/config (audit_ok); плашка видна на всех экранах.

// setAuditBadge показывает или скрывает плашку «журнал аудита нарушен».
export function setAuditBadge(el: HTMLElement, ok: boolean): void {
  el.classList.add('audit-badge');
  el.hidden = ok;
  if (!ok) el.textContent = 'журнал аудита нарушен';
}
