import { create } from "zustand";
import type { DemoState } from "../../../shared/types";

interface Store {
  demo: DemoState | null;
  connected: boolean;
  connect: () => void;
}

export const useStore = create<Store>((set) => ({
  demo: null,
  connected: false,
  connect: () => {
    const es = new EventSource("/api/events");
    es.onopen = () => set({ connected: true });
    es.onerror = () => set({ connected: false });
    es.onmessage = (e) => set({ demo: JSON.parse(e.data) as DemoState });
  },
}));
