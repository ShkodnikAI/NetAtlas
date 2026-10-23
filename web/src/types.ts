// Общие типы серверных ответов, не покрытые api.ts.

export interface storeAlert {
  id: number;
  device_id: string;
  created: string;
  open: boolean;
}
