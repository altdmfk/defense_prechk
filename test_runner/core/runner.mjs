export const testRegistry = [];
export const setupHooks = [];

export function testScenario(wave, attackId, description, fn) {
  testRegistry.push({ wave, attackId, description, fn });
}

export function beforeAll(fn) {
  setupHooks.push(fn);
}
