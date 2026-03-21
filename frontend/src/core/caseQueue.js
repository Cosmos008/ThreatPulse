export function syncCaseQueue(queue = [], cases = [], activeStatuses = []) {
  const activeIds = new Set(
    (Array.isArray(cases) ? cases : [])
      .filter(entry => activeStatuses.includes(String(entry.status || "").toLowerCase()))
      .map(entry => String(entry.id))
  );
  return (Array.isArray(queue) ? queue : []).map(String).filter(caseId => activeIds.has(caseId));
}

export function toggleCaseQueue(queue = [], caseId, isSelected) {
  const normalizedCaseId = String(caseId || "");
  const nextQueue = (Array.isArray(queue) ? queue : []).map(String).filter(Boolean);
  if (!normalizedCaseId) {
    return nextQueue;
  }
  if (isSelected) {
    return nextQueue.includes(normalizedCaseId) ? nextQueue : [...nextQueue, normalizedCaseId];
  }
  return nextQueue.filter(entry => entry !== normalizedCaseId);
}

export function getNextQueuedCaseId(queue = [], currentCaseId = null) {
  const normalizedQueue = (Array.isArray(queue) ? queue : []).map(String).filter(Boolean);
  if (!normalizedQueue.length) {
    return null;
  }
  if (!currentCaseId) {
    return normalizedQueue[0];
  }
  const currentIndex = normalizedQueue.findIndex(caseId => caseId === String(currentCaseId));
  if (currentIndex === -1) {
    return normalizedQueue[0];
  }
  return normalizedQueue[currentIndex + 1] || normalizedQueue[currentIndex - 1] || null;
}

export function getQueueVisibleCaseId(queue = [], filteredCases = []) {
  const visibleIds = new Set((Array.isArray(filteredCases) ? filteredCases : []).map(entry => String(entry.id)));
  return (Array.isArray(queue) ? queue : []).map(String).find(caseId => visibleIds.has(caseId)) || null;
}

export function getQueuePosition(queue = [], caseId) {
  const normalizedQueue = (Array.isArray(queue) ? queue : []).map(String).filter(Boolean);
  const index = normalizedQueue.findIndex(entry => entry === String(caseId || ""));
  if (index === -1) {
    return null;
  }
  return {
    index: index + 1,
    total: normalizedQueue.length
  };
}
