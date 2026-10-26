import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import {
  api,
  type Site,
  type ExceptionRule,
  type ACLRule,
  type PolicySettings,
  type ConfigDiffItem,
  type ConfigHistoryItem,
  type ManagedCertificate,
  type CertificatePayload,
} from '@/api/client';

export const useConfigStore = defineStore('config', () => {
  const sites = ref<Site[]>([]);
  const certificates = ref<ManagedCertificate[]>([]);
  const exceptions = ref<ExceptionRule[]>([]);
  const acls = ref<ACLRule[]>([]);
  const policies = ref<PolicySettings | null>(null);
  const diffs = ref<ConfigDiffItem[]>([]);
  const history = ref<ConfigHistoryItem[]>([]);
  const cluster = ref<{ mode: string; redis_connected: boolean; active_version: number; channel: string } | null>(null);

  const loading = ref(false);
  const error = ref<string | null>(null);

  const hasDraftChanges = computed(() => diffs.value.length > 0);
  const activeVersion = computed(() => cluster.value?.active_version || (history.value.length > 0 ? history.value[0].version : 1));

  async function loadAll() {
    loading.value = true;
    error.value = null;
    try {
      const [sitesData, exceptionsData, aclsData, policiesData, diffData, historyData, clusterData, certData] =
        await Promise.allSettled([
          api.listSites(),
          api.listExceptions(),
          api.listACLs(),
          api.getPolicies(),
          api.getDraftDiff(),
          api.getConfigHistory(),
          api.getClusterStatus(),
          api.listCertificates(),
        ]);

      if (sitesData.status === 'fulfilled') sites.value = sitesData.value;
      if (exceptionsData.status === 'fulfilled') exceptions.value = exceptionsData.value;
      if (aclsData.status === 'fulfilled') acls.value = aclsData.value;
      if (policiesData.status === 'fulfilled') policies.value = policiesData.value;
      if (diffData.status === 'fulfilled') diffs.value = diffData.value.diffs;
      if (historyData.status === 'fulfilled') history.value = historyData.value;
      if (clusterData.status === 'fulfilled') cluster.value = clusterData.value;
      if (certData.status === 'fulfilled') certificates.value = certData.value;
    } catch (err: unknown) {
      error.value = err instanceof Error ? err.message : 'Failed to load configuration';
    } finally {
      loading.value = false;
    }
  }

  async function refreshDiff() {
    try {
      const res = await api.getDraftDiff();
      diffs.value = res.diffs;
    } catch {
      // ignore
    }
  }

  // Sites
  async function createSite(site: Partial<Site>) {
    const created = await api.createSite(site);
    sites.value.push(created);
    await refreshDiff();
    return created;
  }

  async function updateSite(id: string, site: Partial<Site>) {
    const updated = await api.updateSite(id, site);
    const idx = sites.value.findIndex((s) => s.id === id);
    if (idx !== -1) sites.value[idx] = updated;
    await refreshDiff();
    return updated;
  }

  async function deleteSite(id: string) {
    await api.deleteSite(id);
    sites.value = sites.value.filter((s) => s.id !== id);
    await refreshDiff();
  }

  // Exceptions
  async function createException(rule: Partial<ExceptionRule>) {
    const created = await api.createException(rule);
    exceptions.value.push(created);
    await refreshDiff();
    return created;
  }

  async function deleteException(id: string) {
    await api.deleteException(id);
    exceptions.value = exceptions.value.filter((e) => e.id !== id);
    await refreshDiff();
  }

  // ACLs
  async function createACL(rule: Partial<ACLRule>) {
    const created = await api.createACL(rule);
    acls.value.push(created);
    await refreshDiff();
    return created;
  }

  async function updateACL(id: string, rule: Partial<ACLRule>) {
    const updated = await api.updateACL(id, rule);
    const idx = acls.value.findIndex((a) => a.id === id);
    if (idx !== -1) acls.value[idx] = updated;
    await refreshDiff();
    return updated;
  }

  async function deleteACL(id: string) {
    await api.deleteACL(id);
    acls.value = acls.value.filter((a) => a.id !== id);
    await refreshDiff();
  }

  // Policies
  async function savePolicies(newPolicies: Partial<PolicySettings>) {
    const updated = await api.updatePolicies(newPolicies);
    policies.value = updated;
    await refreshDiff();
    return updated;
  }

  // TLS certificates
  async function loadCertificates() {
    certificates.value = await api.listCertificates();
    return certificates.value;
  }

  async function createCertificate(payload: CertificatePayload) {
    const created = await api.createCertificate(payload);
    certificates.value.push(created);
    await refreshDiff();
    return created;
  }

  async function updateCertificate(id: string, payload: Partial<CertificatePayload>) {
    const updated = await api.updateCertificate(id, payload);
    const idx = certificates.value.findIndex((c) => c.id === id);
    if (idx !== -1) certificates.value[idx] = updated;
    return updated;
  }

  async function deleteCertificate(id: string) {
    await api.deleteCertificate(id);
    certificates.value = certificates.value.filter((c) => c.id !== id);
    return certificates.value;
  }

  async function renewCertificate(id: string) {
    const renewed = await api.renewCertificate(id);
    const idx = certificates.value.findIndex((c) => c.id === id);
    if (idx !== -1) certificates.value[idx] = renewed;
    await refreshDiff();
    return renewed;
  }

  // Deploy & Rollback
  async function applyDraft(author: string, description: string) {
    const result = await api.applyConfig({ author, description });
    await loadAll();
    return result;
  }

  async function rollbackTo(version: number) {
    const result = await api.rollbackConfig(version);
    await loadAll();
    return result;
  }

  return {
    sites,
    certificates,
    exceptions,
    acls,
    policies,
    diffs,
    history,
    cluster,
    loading,
    error,
    hasDraftChanges,
    activeVersion,
    loadAll,
    refreshDiff,
    createSite,
    updateSite,
    deleteSite,
    loadCertificates,
    createCertificate,
    updateCertificate,
    deleteCertificate,
    renewCertificate,
    createException,
    deleteException,
    createACL,
    updateACL,
    deleteACL,
    savePolicies,
    applyDraft,
    rollbackTo,
  };
});
