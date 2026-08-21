import localData from './SumPatches_output.json';

const API_BASE = "http://localhost:20000/api";

/**
 * Returns all vulnerability and crash records.
 */
export const getAllData = () => {
  return localData || [];
};

/**
 * Filter data by Month (e.g. '2024-01') and optional source filter ('all' | 'asb' | 'fuzzer').
 */
export const getDataByMonth = (monthId, sourceFilter = "all") => {
  if (!monthId) return [];
  const [year, month] = monthId.split('-');
  
  return (localData || []).filter(item => {
    if (!item.date) return false;
    const itemDate = new Date(item.date);
    const matchesMonth = itemDate.getFullYear() === parseInt(year) && 
                         (itemDate.getMonth() + 1) === parseInt(month);
    if (!matchesMonth) return false;

    if (sourceFilter === "fuzzer") {
      return item.source === "fuzzer" || (item.cve_id && item.cve_id.startsWith("CRASH-"));
    } else if (sourceFilter === "asb") {
      return item.source === "asb" || (!item.source && !item.cve_id?.startsWith("CRASH-"));
    }
    return true;
  });
};

/**
 * Filter data by component section (e.g. 'kernel', 'framework', 'vendor', 'media').
 */
export const getDataBySection = (sectionId, sourceFilter = "all") => {
  if (!sectionId) return [];
  const normalizedSection = sectionId.toLowerCase().replace(/-/g, ' ');

  return (localData || []).filter(item => {
    const comp = (item.components || '').toLowerCase();
    const matchesSection = comp.includes(normalizedSection) || 
                          (normalizedSection === "framework" && comp.includes("system server"));
    if (!matchesSection) return false;

    if (sourceFilter === "fuzzer") {
      return item.source === "fuzzer" || (item.cve_id && item.cve_id.startsWith("CRASH-"));
    } else if (sourceFilter === "asb") {
      return item.source === "asb" || (!item.source && !item.cve_id?.startsWith("CRASH-"));
    }
    return true;
  });
};

/**
 * Returns all Fuzzer-discovered crashes.
 */
export const getFuzzerCrashes = () => {
  return (localData || []).filter(item => item.source === "fuzzer" || item.cve_id?.startsWith("CRASH-"));
};

/**
 * Calculates global stats for the platform.
 */
export const getPlatformStats = () => {
  const all = localData || [];
  const fuzzerItems = all.filter(item => item.source === "fuzzer" || item.cve_id?.startsWith("CRASH-"));
  const asbItems = all.filter(item => item.source !== "fuzzer" && !item.cve_id?.startsWith("CRASH-"));

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