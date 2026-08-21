import localData from './SumPatches_output.json';

const API_BASE = "http://localhost:20000/api";

/**
 * A record is a "finding" only if it is published.
 * ASB reference records (source === 'asb') are always published — they are
 * official bulletins. Fuzzer records must pass the lifecycle
 * (ingested -> analyzed -> pending_review -> published) before they appear.
 */
const isPublished = (item) => {
  if (item.source === "asb" || (item.cve_id && !item.cve_id.startsWith("CRASH-"))) {
    return true;
  }
  return item.status === "published";
};

const isFuzzer = (item) => item.source === "fuzzer" || (item.cve_id && item.cve_id.startsWith("CRASH-"));

/**
 * Returns all published vulnerability and crash records.
 */
export const getAllData = () => {
  return (localData || []).filter(isPublished);
};

/**
 * Filter data by Month (e.g. '2024-01') and optional source filter ('all' | 'asb' | 'fuzzer').
 * Only published records are returned.
 */
export const getDataByMonth = (monthId, sourceFilter = "all") => {
  if (!monthId) return [];
  const [year, month] = monthId.split('-');

  return (localData || []).filter(item => {
    if (!isPublished(item)) return false;
    if (!item.date) return false;
    const itemDate = new Date(item.date);
    const matchesMonth = itemDate.getFullYear() === parseInt(year) &&
                         (itemDate.getMonth() + 1) === parseInt(month);
    if (!matchesMonth) return false;

    if (sourceFilter === "fuzzer") return isFuzzer(item);
    if (sourceFilter === "asb") return !isFuzzer(item);
    return true;
  });
};

/**
 * Filter data by component section (e.g. 'kernel', 'framework', 'vendor', 'media').
 * Only published records are returned.
 */
export const getDataBySection = (sectionId, sourceFilter = "all") => {
  if (!sectionId) return [];
  const normalizedSection = sectionId.toLowerCase().replace(/-/g, ' ');

  return (localData || []).filter(item => {
    if (!isPublished(item)) return false;
    const comp = (item.components || '').toLowerCase();
    const matchesSection = comp.includes(normalizedSection) ||
                          (normalizedSection === "framework" && comp.includes("system server"));
    if (!matchesSection) return false;

    if (sourceFilter === "fuzzer") return isFuzzer(item);
    if (sourceFilter === "asb") return !isFuzzer(item);
    return true;
  });
};

/**
 * Returns all published Fuzzer-discovered crashes.
 */
export const getFuzzerCrashes = () => {
  return (localData || []).filter(item => isFuzzer(item) && isPublished(item));
};

/**
 * Returns fuzzer crashes that are still in the review pipeline (not yet published).
 */
export const getPendingReviewCrashes = () => {
  return (localData || []).filter(item =>
    isFuzzer(item) && item.status && item.status !== "published" && item.status !== "rejected"
  );
};

/**
 * Calculates global stats for the platform (published findings only).
 */
export const getPlatformStats = () => {
  const all = (localData || []).filter(isPublished);
  const fuzzerItems = all.filter(isFuzzer);
  const asbItems = all.filter(item => !isFuzzer(item));

  const severityCounts = all.reduce((acc, item) => {
    const sev = (item.severity || "unknown").toLowerCase();
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  return {
    total: all.length,
    asbCount: asbItems.length,
    fuzzerCount: fuzzerItems.length,
    severities: severityCounts
  };
};
