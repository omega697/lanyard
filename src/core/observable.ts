import type { LanyardWritable } from "./models.js";

/**
 * Creates a lightweight reactive store that conforms to Svelte's `{ subscribe }` store contract
 * without requiring `svelte` as a runtime dependency.
 */
export function createWritableStore<T>(initialValue: T): LanyardWritable<T> {
  let value = initialValue;
  const subscribers = new Set<(val: T) => void>();

  function set(newValue: T): void {
    value = newValue;
    for (const sub of Array.from(subscribers)) {
      if (subscribers.has(sub)) {
        sub(value);
      }
    }
  }

  function update(updater: (current: T) => T): void {
    set(updater(value));
  }

  function subscribe(run: (val: T) => void): () => void {
    subscribers.add(run);
    run(value);
    return () => {
      subscribers.delete(run);
    };
  }

  function get(): T {
    return value;
  }

  return {
    subscribe,
    set,
    update,
    get
  };
}
