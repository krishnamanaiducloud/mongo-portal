// Stand-in for Node modules (fs, v8) referenced on code paths that never
// run in the browser shell (for example load() and heap statistics).
function unavailable(): never {
  throw new Error('This feature is not available in the portal shell');
}

export const readFileSync = unavailable;
export const existsSync = () => false;
export const promises = {};
export const getHeapStatistics = unavailable;
export default { readFileSync, existsSync, promises, getHeapStatistics };
