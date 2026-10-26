import { computed, ref, watch } from 'vue';
import type { ListeningPort, ManagedCertificate, Site, Upstream } from '@/api/client';

export interface PortEntry extends ListeningPort {
  id: string;
}

export interface UpstreamEntry {
  id: string;
  dial: string;
  weight: number;
}

export type SslMode = 'none' | 'auto' | 'manual';
export type RoutingType = 'proxy' | 'static' | 'redirect';
export type LoadBalancing = 'round_robin' | 'least_conn' | 'ip_hash' | 'primary_backup';
export type RunMode = 'defense' | 'audit' | 'offline';

const DEFAULT_PORTS: ListeningPort[] = [
  { port: 80, scheme: 'http' },
  { port: 443, scheme: 'https' },
];

const newId = () => Math.random().toString(36).slice(2, 9);

const stripScheme = (raw: string): string => {
  let dial = raw.trim();
  dial = dial.replace(/^https?:\/\//, '');
  const slash = dial.indexOf('/');
  return slash === -1 ? dial : dial.slice(0, slash);
};

const isValidDial = (dial: string): boolean => {
  if (dial.startsWith('unix:')) return dial.length > 'unix:'.length;
  const match = /^([^:\s]+):(\d{1,5})$/.exec(dial);
  if (!match) return false;
  const port = Number(match[2]);
  return port > 0 && port <= 65535;
};

const isValidRedirect = (target: string): boolean => {
  const value = target.trim();
  if (!value || value.startsWith('//')) return false;
  if (value.startsWith('/')) return true;
  return /^https?:\/\/[^\s]+$/.test(value);
};

const coversHost = (cert: ManagedCertificate, host: string): boolean => {
  const clean = host.trim().toLowerCase();
  return cert.domains.some((domain) => {
    const pattern = domain.trim().toLowerCase();
    if (pattern === clean) return true;
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(1);
      return clean.endsWith(suffix) && clean.indexOf('.') === clean.length - suffix.length - 1;
    }
    return false;
  });
};

// useSiteForm owns the application form state, hydration from an existing
// site, and payload compilation/validation for the create/edit dialog.
export function useSiteForm(siteSource: () => Site | null | undefined) {
  const appName = ref('');
  const appDescription = ref('');
  const domains = ref<string[]>(['*']);
  const domainInput = ref('');
  const ports = ref<PortEntry[]>([]);
  const sslMode = ref<SslMode>('auto');
  const certificateId = ref('');
  const routingType = ref<RoutingType>('proxy');
  const upstreams = ref<UpstreamEntry[]>([]);
  const loadBalancing = ref<LoadBalancing>('round_robin');
  const documentRoot = ref('');
  const redirectUrl = ref('');
  const redirectStatus = ref(302);
  const formMode = ref<RunMode>('defense');
  const formBlockCode = ref(403);
  const formOfflineCode = ref(503);
  const advancedOpen = ref(false);
  const validationError = ref('');

  const hasHttpsPort = computed(() => ports.value.some((p) => p.scheme === 'https'));

  const reset = () => {
    appName.value = '';
    appDescription.value = '';
    domains.value = ['*'];
    domainInput.value = '';
    ports.value = DEFAULT_PORTS.map((p) => ({ ...p, id: newId() }));
    sslMode.value = 'auto';
    certificateId.value = '';
    routingType.value = 'proxy';
    upstreams.value = [{ id: newId(), dial: 'http://127.0.0.1:8080', weight: 1 }];
    loadBalancing.value = 'round_robin';
    documentRoot.value = '';
    redirectUrl.value = '';
    redirectStatus.value = 302;
    formMode.value = 'defense';
    formBlockCode.value = 403;
    formOfflineCode.value = 503;
    advancedOpen.value = false;
    validationError.value = '';
  };

  const hydrate = (site: Site) => {
    appName.value = site.name || '';
    appDescription.value = site.description || '';
    domains.value = site.hostnames?.length ? [...site.hostnames] : ['*'];
    domainInput.value = '';

    const sourcePorts = site.ports?.length ? site.ports : DEFAULT_PORTS;
    ports.value = sourcePorts.map((p) => ({ port: p.port, scheme: p.scheme, id: newId() }));

    sslMode.value = site.ssl_mode || (sourcePorts.some((p) => p.scheme === 'https') ? 'auto' : 'none');
    certificateId.value = site.certificate_id || '';
    routingType.value = site.routing_type || 'proxy';
    loadBalancing.value = site.load_balancing || 'round_robin';
    documentRoot.value = site.document_root || '';
    redirectUrl.value = site.redirect_url || '';
    redirectStatus.value = site.redirect_status || 302;
    formMode.value = site.mode || 'defense';
    formBlockCode.value = site.block_status_code || 403;
    formOfflineCode.value = site.offline_status_code || 503;
    advancedOpen.value = false;
    validationError.value = '';

    upstreams.value = site.upstreams?.length
      ? site.upstreams.map((u) => ({
          id: newId(),
          dial: u.dial.includes('://') ? u.dial : `http://${u.dial}`,
          weight: u.weight || 1,
        }))
      : [{ id: newId(), dial: 'http://127.0.0.1:8080', weight: 1 }];
  };

  watch(
    siteSource,
    (val) => {
      if (val) hydrate(val);
      else reset();
    },
    { immediate: true }
  );

  const addDomain = () => {
    const raw = domainInput.value.trim();
    if (!raw) return;
    for (const part of raw.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)) {
      if (!domains.value.includes(part)) domains.value.push(part);
    }
    domainInput.value = '';
  };

  const removeDomain = (idx: number) => {
    domains.value.splice(idx, 1);
    if (domains.value.length === 0) domains.value = ['*'];
  };

  const addPort = () => {
    const highest = ports.value.length > 0 ? Math.max(...ports.value.map((p) => p.port)) : 79;
    const next = highest < 65535 ? highest + 1 : 8080;
    ports.value.push({ id: newId(), port: next, scheme: 'http' });
  };

  const removePort = (idx: number) => {
    if (ports.value.length > 1) ports.value.splice(idx, 1);
  };

  const addUpstream = () => {
    upstreams.value.push({ id: newId(), dial: 'http://127.0.0.1:8080', weight: 1 });
  };

  const removeUpstream = (idx: number) => {
    if (upstreams.value.length > 1) upstreams.value.splice(idx, 1);
  };

  // certificatesForHosts splits certificates into those that cover every
  // hostname (selectable) and those that do not (shown disabled so operators
  // understand why they cannot be used).
  const certificateGroups = (certs: ManagedCertificate[]) => {
    const hosts = domains.value.filter((h) => h !== '*' && h.trim() !== '');
    const usable: ManagedCertificate[] = [];
    const unusable: ManagedCertificate[] = [];
    for (const cert of certs) {
      const covers = hosts.every((h) => coversHost(cert, h));
      (covers ? usable : unusable).push(cert);
    }
    usable.sort((a, b) => a.name.localeCompare(b.name));
    unusable.sort((a, b) => a.name.localeCompare(b.name));
    return { usable, unusable };
  };

  const buildPayload = (): { payload?: Partial<Site>; error?: string } => {
    addDomain();
    const hostnames = domains.value.filter((h) => h.trim() !== '');
    if (hostnames.length === 0) return { error: 'Add at least one hostname.' };

    const cleanPorts: ListeningPort[] = ports.value.map((p) => ({ port: Number(p.port), scheme: p.scheme }));
    if (cleanPorts.some((p) => !Number.isInteger(p.port) || p.port < 1 || p.port > 65535)) {
      return { error: 'Listening ports must be between 1 and 65535.' };
    }
    const https = cleanPorts.some((p) => p.scheme === 'https');

    let mode: SslMode = sslMode.value;
    if (!https) mode = 'none';
    else if (mode === 'none') return { error: 'An HTTPS listener requires TLS. Choose Auto or Manual.' };
    if (mode === 'manual' && !certificateId.value) return { error: 'Select a managed certificate for manual TLS.' };

    const compiled: Upstream[] = [];
    if (routingType.value === 'proxy') {
      for (const entry of upstreams.value) {
        const dial = stripScheme(entry.dial);
        if (!dial) return { error: 'Every upstream needs a host:port address.' };
        if (!isValidDial(dial)) return { error: `Invalid upstream address "${dial}". Use host:port or unix:/path.` };
        compiled.push({ dial, weight: Math.min(Math.max(Number(entry.weight) || 1, 1), 100) });
      }
      if (compiled.length === 0) return { error: 'Add at least one upstream.' };
    }

    if (routingType.value === 'static') {
      const root = documentRoot.value.trim();
      if (!root.startsWith('/')) return { error: 'Document root must be an absolute path (for example /srv/www).' };
    }

    if (routingType.value === 'redirect' && !isValidRedirect(redirectUrl.value)) {
      return { error: 'Redirect target must be an absolute URL or a site-relative path.' };
    }

    const finalName = appName.value.trim() || hostnames[0] || 'Application';
    validationError.value = '';
    return {
      payload: {
        id: siteSource()?.id,
        name: finalName,
        description: appDescription.value.trim(),
        hostnames,
        mode: formMode.value,
        ports: cleanPorts,
        ssl_mode: mode,
        certificate_id: mode === 'manual' ? certificateId.value : '',
        routing_type: routingType.value,
        document_root: routingType.value === 'static' ? documentRoot.value.trim() : '',
        redirect_url: routingType.value === 'redirect' ? redirectUrl.value.trim() : '',
        redirect_status: redirectStatus.value,
        load_balancing: loadBalancing.value,
        upstreams: compiled,
        block_status_code: formBlockCode.value,
        offline_status_code: formOfflineCode.value,
      },
    };
  };

  return {
    appName,
    appDescription,
    domains,
    domainInput,
    ports,
    sslMode,
    certificateId,
    routingType,
    upstreams,
    loadBalancing,
    documentRoot,
    redirectUrl,
    redirectStatus,
    formMode,
    formBlockCode,
    formOfflineCode,
    advancedOpen,
    hasHttpsPort,
    validationError,
    addDomain,
    removeDomain,
    addPort,
    removePort,
    addUpstream,
    removeUpstream,
    certificateGroups,
    buildPayload,
  };
}
