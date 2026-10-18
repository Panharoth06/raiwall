<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import {
  Gauge,
  TrendingUp,
  Compass,
  Bell,
  Server,
  ShieldCheck,
  Settings,
  Filter,
  ChevronDown,
  ChevronRight,
  Bot,
  Globe,
  Lock,
  Smartphone,
  Key,
  Minus,
  Info,
} from 'lucide-vue-next'
import { Popover, PopoverTrigger, PopoverContent } from '@/components/ui/popover'
import { Switch } from '@/components/ui/switch'
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import type {
  ViewMode,
  IngressSourceId,
  WafHubId,
  TooltipState,
  ArcNodeItem,
  SankeyRibbon,
} from '@/types/waf-topology'

// Reactive State
const viewMode = ref<ViewMode>('traffic')
const owaspOnly = ref<boolean>(false)
const selectedTenant = ref<string>('PROD-WAF: API-EDGE')
const isHumansExpanded = ref<boolean>(false)
const hoveredBadgeCluster = ref<IngressSourceId | null>(null)
const hoveredHubId = ref<WafHubId | null>(null)
const hoveredRibbonId = ref<string | null>(null)
const hoveredArcNodeId = ref<string | null>(null)

// Tooltip State
const tooltip = reactive<TooltipState>({
  visible: false,
  x: 0,
  y: 0,
  header: '',
  subtext: '',
})

// Tooltip Handlers with boundary clamping to prevent offscreen clipping
const handleShowTooltip = (event: MouseEvent, header: string, subtext: string) => {
  const clientX = event.clientX ?? 400
  const clientY = event.clientY ?? 300
  const tooltipWidth = 275
  const tooltipHeight = 110
  const viewportWidth = typeof window !== 'undefined' ? window.innerWidth : 1600
  const viewportHeight = typeof window !== 'undefined' ? window.innerHeight : 900

  let x = clientX + 16
  let y = clientY + 16

  // If overflowing right edge, flip to left of cursor
  if (x + tooltipWidth > viewportWidth - 16) {
    x = clientX - tooltipWidth - 16
  }
  if (x < 16) {
    x = 16
  }

  // If overflowing bottom edge, flip upward
  if (y + tooltipHeight > viewportHeight - 16) {
    y = clientY - tooltipHeight - 16
  }
  if (y < 16) {
    y = 16
  }

  tooltip.x = Math.round(x)
  tooltip.y = Math.round(y)
  tooltip.header = header
  tooltip.subtext = subtext
  tooltip.visible = true
}

const handleHideTooltip = () => {
  tooltip.visible = false
}

// Reset Filters
const handleResetFilters = () => {
  owaspOnly.value = false
  selectedTenant.value = 'PROD-WAF: API-EDGE'
}

// Left Ingress Data
const botsSubtext = computed(() => {
  return hoveredBadgeCluster.value === 'bots'
    ? '0.1 kB/s • TLS 1.3 Fingerprint'
    : '3.4M Requests (68% Blocked)'
})

const humansSubtext = computed(() => {
  return hoveredBadgeCluster.value === 'humans'
    ? '0.1 kB/s • TLS 1.3 Fingerprint'
    : '18.9M Requests (0.4% Blocked)'
})

const apiSubtext = computed(() => {
  return hoveredBadgeCluster.value === 'api'
    ? '0.1 kB/s • TLS 1.3 Fingerprint'
    : '41.5M Requests (1.2% Blocked)'
})

// Starburst Radial Ticks generator (48 ticks)
const computeHubTicks = (cx: number, cy: number, hubId: WafHubId) => {
  const isHovered = hoveredHubId.value === hubId
  const activeLengthExtension = isHovered ? 8 : 0
  const ticks = []

  for (let i = 0; i < 48; i++) {
    const angle = (i * 360) / 48
    const rad = (angle * Math.PI) / 180
    const r1 = 64
    const isActive = i % 2 === 0

    let r2 = 76
    let color = '#3A4354'
    let strokeWidth = 1.4

    if (isActive) {
      r2 = 90 + activeLengthExtension
      // Left-facing hemisphere 135° to 225° marks terminated threats
      if (angle >= 135 && angle <= 225) {
        color = '#EF4444'
      } else {
        color = '#10B981'
      }
      strokeWidth = 2.2
    }

    const cos = Math.cos(rad)
    const sin = Math.sin(rad)

    ticks.push({
      x1: Number((cx + r1 * cos).toFixed(2)),
      y1: Number((cy + r1 * sin).toFixed(2)),
      x2: Number((cx + r2 * cos).toFixed(2)),
      y2: Number((cy + r2 * sin).toFixed(2)),
      color,
      strokeWidth,
    })
  }

  return ticks
}

const wafCoreTicks = computed(() => computeHubTicks(800, 330, 'waf-core'))
const edgeDefenseTicks = computed(() => computeHubTicks(800, 600, 'edge-defense'))

// Destination & Threat Arc Summaries
const upperSummary = computed(() => {
  if (viewMode.value === 'threats') {
    return {
      count: '4',
      title: 'INJECTION VECTORS',
      subtext: '2.14M Payloads Blocked',
    }
  }
  if (owaspOnly.value) {
    return {
      count: '6',
      title: 'API GATEWAY ROUTES',
      subtext: '90.4k Attack Reqs',
    }
  }
  return {
    count: '24',
    title: 'API GATEWAY ROUTES',
    subtext: '48.2M Reqs Inspected',
  }
})

const lowerSummary = computed(() => {
  if (viewMode.value === 'threats') {
    return {
      count: '4',
      title: 'ABUSE & BOT VECTORS',
      subtext: '1.68M Requests Dropped',
    }
  }
  return {
    count: '14',
    title: 'WEB & MICROSERVICES',
    subtext: '11.9M Reqs Inspected',
  }
})

// Upper Arc Nodes
const upperArcNodes = computed<ArcNodeItem[]>(() => {
  const cx = 1190
  const cy = 330
  const radius = 180

  if (viewMode.value === 'threats') {
    const threats = [
      { id: 'sqli', label: 'SQLi #942100', header: 'INJECTION: SQLi #942100', subtext: '840k payloads neutralized by TiDB AST & libinjection' },
      { id: 'xss', label: 'XSS #941100', header: 'INJECTION: XSS #941100', subtext: '620k attacks blocked via tdewolff/parse context verifier' },
      { id: 'lfi', label: 'LFI #930100', header: 'INJECTION: LFI #930100', subtext: '410k local file inclusion directory traversals halted' },
      { id: 'rce', label: 'RCE #932100', header: 'INJECTION: RCE #932100', subtext: '270k remote command executions prevented by mvdan/sh' },
    ]
    const angles = [-38, -13, 13, 38]
    return threats.map((t, idx) => {
      const rad = (angles[idx] * Math.PI) / 180
      return {
        id: t.id,
        label: t.label,
        category: 'upper',
        x: Number((cx + radius * Math.cos(rad)).toFixed(2)),
        y: Number((cy + radius * Math.sin(rad)).toFixed(2)),
        tooltipHeader: t.header,
        tooltipSubtext: t.subtext,
      }
    })
  }

  if (owaspOnly.value) {
    const targets = [
      { id: 'auth-login', label: '/api/v1/auth/login', method: 'POST' as const, header: '90.4k ATTACK REQUESTS', subtext: '6 upstream routes protected by WAF Core Engine' },
      { id: 'users-search', label: '/api/v1/users/search', method: 'GET' as const, header: '32.1k ATTACK REQUESTS', subtext: 'SQL injection UNION attempts intercepted' },
      { id: 'webhooks-cb', label: '/api/v2/webhooks/callback', method: 'POST' as const, header: '24.8k ATTACK REQUESTS', subtext: 'Malicious signature bypass attempts dropped' },
      { id: 'graphql-attack', label: '/graphql', method: 'POST' as const, header: '18.2k ATTACK REQUESTS', subtext: 'Circular introspective query depth exceeded' },
      { id: 'config-exp', label: '/admin/config/export', method: 'GET' as const, header: '9.4k ATTACK REQUESTS', subtext: 'Unauthorized role privilege escalation halted' },
      { id: 'files-dl', label: '/api/v1/files/download', method: 'GET' as const, header: '5.9k ATTACK REQUESTS', subtext: 'Path traversal directory escape sequence sanitized' },
    ]
    const angles = [-45, -27, -9, 9, 27, 45]
    return targets.map((t, idx) => {
      const rad = (angles[idx] * Math.PI) / 180
      return {
        id: t.id,
        label: t.label,
        category: 'upper',
        method: t.method,
        isAttackTarget: true,
        x: Number((cx + radius * Math.cos(rad)).toFixed(2)),
        y: Number((cy + radius * Math.sin(rad)).toFixed(2)),
        tooltipHeader: t.header,
        tooltipSubtext: t.subtext,
      }
    })
  }

  // Default traffic mode
  const routes = [
    { id: 'auth-token', label: '/api/v1/auth/token', method: 'POST' as const, header: '14.2M REQUESTS (184.2k BLOCKED)', subtext: '72.6k clients, hosts, API keys accessing /api/v1/auth/token' },
    { id: 'payments', label: '/api/v2/payments/transfer', method: 'POST' as const, header: '8.4M REQUESTS (24.1k BLOCKED)', subtext: 'PCI-DSS tokenized transaction endpoint' },
    { id: 'graphql', label: '/graphql', method: 'POST' as const, header: '18.7M REQUESTS (82.9k BLOCKED)', subtext: 'Enterprise federation subgraphs gateway' },
    { id: 'more-api', label: '& 21 more', header: '21 ADDITIONAL ROUTES', subtext: '6.9M aggregate requests across internal microservices' },
  ]
  const angles = [-38, -13, 13, 38]
  return routes.map((r, idx) => {
    const rad = (angles[idx] * Math.PI) / 180
    return {
      id: r.id,
      label: r.label,
      category: 'upper',
      method: r.method,
      x: Number((cx + radius * Math.cos(rad)).toFixed(2)),
      y: Number((cy + radius * Math.sin(rad)).toFixed(2)),
      tooltipHeader: r.header,
      tooltipSubtext: r.subtext,
    }
  })
})

// Lower Arc Nodes
const lowerArcNodes = computed<ArcNodeItem[]>(() => {
  const cx = 1190
  const cy = 600
  const radius = 180

  if (viewMode.value === 'threats') {
    const vectors = [
      { id: 'rate-limit', label: 'Rate Limit 429', header: 'ABUSE: Rate Limit 429', subtext: '890k excessive velocity bursts throttled by Tier-1 limiter' },
      { id: 'cred-stuffing', label: 'Credential Stuffing', header: 'ABUSE: Credential Stuffing', subtext: '450k automated dictionary attacks deflected' },
      { id: 'bad-bot-ja4', label: 'Bad Bot JA4', header: 'ABUSE: Bad Bot JA4', subtext: '220k headless browser TLS fingerprints banned' },
      { id: 'schema-viol', label: 'Schema Violation', header: 'ABUSE: Schema Violation', subtext: '120k malformed JSON payloads rejected at ingress' },
    ]
    const angles = [-38, -13, 13, 38]
    return vectors.map((v, idx) => {
      const rad = (angles[idx] * Math.PI) / 180
      return {
        id: v.id,
        label: v.label,
        category: 'lower',
        x: Number((cx + radius * Math.cos(rad)).toFixed(2)),
        y: Number((cy + radius * Math.sin(rad)).toFixed(2)),
        tooltipHeader: v.header,
        tooltipSubtext: v.subtext,
      }
    })
  }

  const services = [
    { id: 'portal', label: 'portal.internal/dashboard', method: 'GET' as const, header: '5.2M REQUESTS (3.2k BLOCKED)', subtext: 'Primary operator administration interface' },
    { id: 'upload', label: 'upload.internal/media', method: 'POST' as const, header: '2.8M REQUESTS (18.4k BLOCKED)', subtext: 'Direct streaming upload engine with multipart filter' },
    { id: 'realtime', label: 'realtime.internal/stream', method: 'GET' as const, header: '3.1M REQUESTS (1.1k BLOCKED)', subtext: 'Live WebSocket & SSE connection multiplexer' },
    { id: 'more-web', label: '& 11 more', header: '11 ADDITIONAL SERVICES', subtext: '800k requests across background workers' },
  ]
  const angles = [-38, -13, 13, 38]
  return services.map((s, idx) => {
    const rad = (angles[idx] * Math.PI) / 180
    return {
      id: s.id,
      label: s.label,
      category: 'lower',
      method: s.method,
      x: Number((cx + radius * Math.cos(rad)).toFixed(2)),
      y: Number((cy + radius * Math.sin(rad)).toFixed(2)),
      tooltipHeader: s.header,
      tooltipSubtext: s.subtext,
    }
  })
})

// Cubic Bézier calculation: M x1 y1 C cx1 y1, cx2 y2, x2 y2
const computeCubicPath = (x1: number, y1: number, x2: number, y2: number): string => {
  const dx = x2 - x1
  const cx1 = Number((x1 + dx * 0.45).toFixed(2))
  const cx2 = Number((x1 + dx * 0.55).toFixed(2))
  return `M ${x1} ${y1} C ${cx1} ${y1}, ${cx2} ${y2}, ${x2} ${y2}`
}

// Sankey Ribbons
const sankeyRibbons = computed<SankeyRibbon[]>(() => {
  const ribbons: SankeyRibbon[] = []

  // Stage 1: Left Ingress Sources to Center Hubs
  // Bots (270, 200) -> Threats
  ribbons.push({
    id: 'ribbon-bots-wafcore',
    d: computeCubicPath(270, 200, 800, 330),
    sourceId: 'bots',
    targetId: 'waf-core',
    stroke: hoveredRibbonId.value === 'ribbon-bots-wafcore' ? 'rgba(239, 68, 68, 0.60)' : 'rgba(239, 68, 68, 0.28)',
    strokeWidth: 8,
    isThreat: true,
    dimmed: false,
    tooltipHeader: '3.4M BOT REQUESTS (68% BLOCKED)',
    tooltipSubtext: 'Automated crawlers and threat actors routed through WAF Core Engine inspection',
  })

  // Bots to edge defense (Rate limiting / JA4 bot probes)
  const botEdgeDimmed = owaspOnly.value && viewMode.value === 'traffic'
  ribbons.push({
    id: 'ribbon-bots-edgedefense',
    d: computeCubicPath(270, 200, 800, 600),
    sourceId: 'bots',
    targetId: 'edge-defense',
    stroke: hoveredRibbonId.value === 'ribbon-bots-edgedefense' ? 'rgba(239, 68, 68, 0.60)' : 'rgba(239, 68, 68, 0.28)',
    strokeWidth: 6,
    isThreat: true,
    dimmed: botEdgeDimmed,
    tooltipHeader: '1.2M BOT PROBES INTERCEPTED',
    tooltipSubtext: 'Challenged by stateless PoW and TLS JA4 fingerprinting',
  })

  // Humans (270, 460) -> Clean
  const humansDimmed = (owaspOnly.value && viewMode.value === 'traffic') || viewMode.value === 'threats'
  ribbons.push({
    id: 'ribbon-humans-wafcore',
    d: computeCubicPath(270, 460, 800, 330),
    sourceId: 'humans',
    targetId: 'waf-core',
    stroke: hoveredRibbonId.value === 'ribbon-humans-wafcore' ? 'rgba(220, 232, 245, 0.52)' : 'rgba(175, 188, 204, 0.22)',
    strokeWidth: 10,
    isThreat: false,
    dimmed: humansDimmed,
    tooltipHeader: '18.9M HUMAN CLIENT REQUESTS',
    tooltipSubtext: 'Browsers and verified sessions with 0.4% anomaly block rate',
  })

  ribbons.push({
    id: 'ribbon-humans-edgedefense',
    d: computeCubicPath(270, 460, 800, 600),
    sourceId: 'humans',
    targetId: 'edge-defense',
    stroke: hoveredRibbonId.value === 'ribbon-humans-edgedefense' ? 'rgba(220, 232, 245, 0.52)' : 'rgba(175, 188, 204, 0.22)',
    strokeWidth: 8,
    isThreat: false,
    dimmed: humansDimmed,
    tooltipHeader: '9.4M CLIENT CONCURRENCY FLOW',
    tooltipSubtext: 'Tier-1 rate limiting pass-through with valid session tokens',
  })

  // API (270, 730) -> Clean
  const apiDimmed = (owaspOnly.value && viewMode.value === 'traffic') || viewMode.value === 'threats'
  ribbons.push({
    id: 'ribbon-api-wafcore',
    d: computeCubicPath(270, 730, 800, 330),
    sourceId: 'api',
    targetId: 'waf-core',
    stroke: hoveredRibbonId.value === 'ribbon-api-wafcore' ? 'rgba(220, 232, 245, 0.52)' : 'rgba(175, 188, 204, 0.22)',
    strokeWidth: 9,
    isThreat: false,
    dimmed: apiDimmed,
    tooltipHeader: '41.5M API CONSUMER REQUESTS',
    tooltipSubtext: 'Machine-to-machine B2B traffic with valid Bearer tokens',
  })

  ribbons.push({
    id: 'ribbon-api-edgedefense',
    d: computeCubicPath(270, 730, 800, 600),
    sourceId: 'api',
    targetId: 'edge-defense',
    stroke: hoveredRibbonId.value === 'ribbon-api-edgedefense' ? 'rgba(220, 232, 245, 0.52)' : 'rgba(175, 188, 204, 0.22)',
    strokeWidth: 7,
    isThreat: false,
    dimmed: apiDimmed,
    tooltipHeader: '18.2M API GATEWAY RATE MONITORED',
    tooltipSubtext: 'Quota management and CGNAT-safe key balancing',
  })

  // Stage 2: Hubs to Right Arcs
  // Upper Hub (800, 330) -> Upper Arc Nodes
  upperArcNodes.value.forEach((node, idx) => {
    const isThreatMode = viewMode.value === 'threats'
    const isThreat = isThreatMode || owaspOnly.value
    const ribbonId = `ribbon-upper-${idx}`
    const isHovered = hoveredRibbonId.value === ribbonId

    let stroke = isThreat
      ? (isHovered ? 'rgba(239, 68, 68, 0.60)' : 'rgba(239, 68, 68, 0.28)')
      : (isHovered ? 'rgba(220, 232, 245, 0.52)' : 'rgba(175, 188, 204, 0.22)')

    ribbons.push({
      id: ribbonId,
      d: computeCubicPath(800, 330, node.x, node.y),
      sourceId: 'waf-core',
      targetId: node.id,
      stroke,
      strokeWidth: isThreat ? 6 : 5,
      isThreat,
      dimmed: false,
      tooltipHeader: node.tooltipHeader,
      tooltipSubtext: node.tooltipSubtext,
    })
  })

  // Lower Hub (800, 600) -> Lower Arc Nodes
  lowerArcNodes.value.forEach((node, idx) => {
    const isThreat = viewMode.value === 'threats'
    const ribbonId = `ribbon-lower-${idx}`
    const isHovered = hoveredRibbonId.value === ribbonId
    const dimmed = owaspOnly.value && viewMode.value === 'traffic'

    let stroke = isThreat
      ? (isHovered ? 'rgba(239, 68, 68, 0.60)' : 'rgba(239, 68, 68, 0.28)')
      : (isHovered ? 'rgba(220, 232, 245, 0.52)' : 'rgba(175, 188, 204, 0.22)')

    ribbons.push({
      id: ribbonId,
      d: computeCubicPath(800, 600, node.x, node.y),
      sourceId: 'edge-defense',
      targetId: node.id,
      stroke,
      strokeWidth: isThreat ? 6 : 4.5,
      isThreat,
      dimmed,
      tooltipHeader: node.tooltipHeader,
      tooltipSubtext: node.tooltipSubtext,
    })
  })

  return ribbons
})

// Toggle Human drill-down
const toggleHumansExpanded = () => {
  isHumansExpanded.value = !isHumansExpanded.value
}
</script>

<template>
  <div
    data-testid="waf-dashboard-root"
    class="w-screen h-screen overflow-hidden relative select-none flex bg-[#080A0C] font-sans antialiased"
    style="background: radial-gradient(circle at 52% 75%, rgba(16, 65, 48, 0.20) 0%, rgba(8, 10, 12, 0) 65%), #080A0C;"
  >
    <!-- Left Navigation Rail (56px) -->
    <aside
      data-testid="nav-rail"
      class="w-14 h-full bg-[#11141A] border-r border-[#1E232D] flex flex-col items-center z-30 shrink-0 select-none"
    >
      <!-- Top Brand Mark: Centered geometric shield/hex SVG in #FFC000 -->
      <div class="mt-4 mb-6 flex items-center justify-center">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" class="w-6 h-6">
          <path
            d="M12 2L4 6V12C4 16.5 7.4 20.6 12 22C16.6 20.6 20 16.5 20 12V6L12 2Z"
            fill="#FFC000"
            stroke="#B48200"
            stroke-width="1.5"
            stroke-linejoin="round"
          />
          <path
            d="M12 6L7 11H11V18L16 13H12V6Z"
            fill="#11141A"
          />
        </svg>
      </div>

      <!-- 7 Vertical Navigation Icon Buttons -->
      <nav class="flex-1 w-full flex flex-col gap-1 items-center">
        <!-- 1. Gauge (Active Command Center) -->
        <button
          class="w-full h-11 flex items-center justify-center relative bg-[#17223B] text-white cursor-pointer group"
          title="Command Center"
        >
          <div class="absolute left-0 top-0 bottom-0 w-[3px] bg-[#2574F5]"></div>
          <Gauge class="w-5 h-5 text-white" />
        </button>

        <!-- 2. TrendingUp + ChevronRight -->
        <button
          class="w-full h-11 flex items-center justify-center relative text-[#848D9C] hover:text-white hover:bg-[#1E222A] cursor-pointer group"
          title="Analytics"
        >
          <div class="flex items-center">
            <TrendingUp class="w-5 h-5" />
            <ChevronRight class="w-2.5 h-2.5 -mr-1" />
          </div>
        </button>

        <!-- 3. Compass -->
        <button
          class="w-full h-11 flex items-center justify-center text-[#848D9C] hover:text-white hover:bg-[#1E222A] cursor-pointer group"
          title="Route Explorer"
        >
          <Compass class="w-5 h-5" />
        </button>

        <!-- 4. Bell + ChevronRight -->
        <button
          class="w-full h-11 flex items-center justify-center relative text-[#848D9C] hover:text-white hover:bg-[#1E222A] cursor-pointer group"
          title="Alerts"
        >
          <div class="flex items-center">
            <Bell class="w-5 h-5" />
            <ChevronRight class="w-2.5 h-2.5 -mr-1" />
          </div>
        </button>

        <!-- 5. Server + ChevronRight -->
        <button
          class="w-full h-11 flex items-center justify-center relative text-[#848D9C] hover:text-white hover:bg-[#1E222A] cursor-pointer group"
          title="Upstreams"
        >
          <div class="flex items-center">
            <Server class="w-5 h-5" />
            <ChevronRight class="w-2.5 h-2.5 -mr-1" />
          </div>
        </button>

        <!-- 6. ShieldCheck + ChevronRight -->
        <button
          class="w-full h-11 flex items-center justify-center relative text-[#848D9C] hover:text-white hover:bg-[#1E222A] cursor-pointer group"
          title="Security Rules"
        >
          <div class="flex items-center">
            <ShieldCheck class="w-5 h-5" />
            <ChevronRight class="w-2.5 h-2.5 -mr-1" />
          </div>
        </button>

        <!-- 7. Settings + ChevronRight -->
        <button
          class="w-full h-11 flex items-center justify-center relative text-[#848D9C] hover:text-white hover:bg-[#1E222A] cursor-pointer group"
          title="Settings"
        >
          <div class="flex items-center">
            <Settings class="w-5 h-5" />
            <ChevronRight class="w-2.5 h-2.5 -mr-1" />
          </div>
        </button>
      </nav>
    </aside>

    <!-- Main Command Center Canvas Area -->
    <main class="flex-1 h-full relative overflow-hidden">
      <!-- Floating Top Bar Overlay (h-14) -->
      <header class="h-14 absolute top-0 left-0 right-0 flex items-center justify-between px-6 z-20 pointer-events-auto">
        <!-- Left: Brand / Title -->
        <div class="flex items-center gap-2">
          <span class="text-xs uppercase tracking-widest font-semibold text-[#B0B8C4]">RAIWALL</span>
          <span class="text-xs text-[#363D4C]">/</span>
          <span class="text-xs font-medium text-white">COMMAND CENTER</span>
        </div>

        <!-- Top-Center View Switcher -->
        <div class="absolute left-1/2 -translate-x-1/2 flex items-center bg-[#15181F] border border-[#2A303C] rounded-full p-1 shadow-lg">
          <button
            data-testid="mode-btn-traffic"
            :class="[
              'rounded-full px-4 py-1 text-xs font-medium transition-all cursor-pointer',
              viewMode === 'traffic'
                ? 'bg-[#2C323F] text-white shadow-sm'
                : 'text-[#848D9C] hover:text-white'
            ]"
            @click="viewMode = 'traffic'"
          >
            Traffic
          </button>
          <button
            data-testid="mode-btn-threats"
            :class="[
              'rounded-full px-4 py-1 text-xs font-medium transition-all cursor-pointer',
              viewMode === 'threats'
                ? 'bg-[#2C323F] text-white shadow-sm'
                : 'text-[#848D9C] hover:text-white'
            ]"
            @click="viewMode = 'threats'"
          >
            Threats
          </button>
        </div>

        <!-- Top-Right Telemetry & Filter Bar -->
        <div class="flex items-center gap-4">
          <!-- Live Status -->
          <div class="flex items-center gap-2">
            <span class="relative flex h-2 w-2">
              <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#10B981] opacity-75"></span>
              <span class="relative inline-flex rounded-full h-2 w-2 bg-[#10B981]"></span>
            </span>
            <Badge variant="outline" class="border-[#10B981]/30 bg-[#10B981]/10 text-[#10B981] px-1.5 py-0 text-[10px] font-bold tracking-wider">LIVE</Badge>
            <span class="text-xs text-[#848D9C] hidden md:inline">Last Updated 16:12:56</span>
          </div>

          <!-- Filter Popover -->
          <Popover>
            <PopoverTrigger as-child>
              <button
                data-testid="filter-trigger-btn"
                class="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-[#363D4C] bg-[#1E222A] hover:bg-[#2A303C] text-xs font-medium text-white shadow transition-colors cursor-pointer"
              >
                <Filter class="w-3.5 h-3.5 text-[#848D9C]" />
                <span>{{ owaspOnly ? 'Filters: 1' : 'Filters' }}</span>
              </button>
            </PopoverTrigger>
            <PopoverContent
              align="end"
              class="w-[260px] bg-[#1E222A] border border-[#363D4C] text-white p-4 shadow-2xl rounded-md"
            >
              <!-- Popover Header -->
              <div class="flex items-center justify-between pb-3 border-b border-[#363D4C] mb-3">
                <span class="text-xs font-semibold uppercase tracking-wider text-[#B0B8C4]">More Filters</span>
                <button
                  data-testid="filter-reset-btn"
                  class="text-xs text-[#60A5FA] hover:underline font-medium cursor-pointer"
                  @click="handleResetFilters"
                >
                  Reset
                </button>
              </div>

              <!-- Tenant Select -->
              <div class="space-y-1.5 mb-4">
                <label class="text-[11px] font-semibold text-[#848D9C] uppercase tracking-wider block">
                  VIRTUAL HOST / TENANT
                </label>
                <Select v-model="selectedTenant">
                  <SelectTrigger class="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="PROD-WAF: API-EDGE">PROD-WAF: API-EDGE</SelectItem>
                    <SelectItem value="STAGING-WAF: WEB">STAGING-WAF: WEB</SelectItem>
                    <SelectItem value="DEV-GATEWAY">DEV-GATEWAY</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <!-- OWASP Filter Switch -->
              <div class="flex items-center justify-between pt-1">
                <label for="owasp-filter" class="text-xs text-[#B0B8C4] cursor-pointer">
                  OWASP Top 10 Attacks only
                </label>
                <div class="flex items-center gap-2">
                  <Switch
                    id="owasp-filter"
                    data-testid="owasp-filter-switch"
                    v-model:checked="owaspOnly"
                  />
                  <span class="text-xs font-medium text-[#848D9C] w-6">
                    {{ owaspOnly ? 'ON' : 'OFF' }}
                  </span>
                </div>
              </div>
            </PopoverContent>
          </Popover>

          <!-- Time Range Selector -->
          <button class="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-[#363D4C] bg-[#1E222A] hover:bg-[#2A303C] text-xs font-medium text-white shadow transition-colors cursor-pointer">
            <span>Past 30 Days</span>
            <ChevronDown class="w-3.5 h-3.5 text-[#848D9C]" />
          </button>
        </div>
      </header>

      <!-- Three-Column Reactive SVG Topology (viewBox 0 0 1600 900) -->
      <div class="w-full h-full flex items-center justify-center">
        <svg
          class="w-full h-full max-w-full max-h-full block"
          viewBox="0 0 1600 900"
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            <!-- Radial ambient glow filter -->
            <radialGradient id="hubGlowEmerald" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stop-color="#10B981" stop-opacity="0.35" />
              <stop offset="100%" stop-color="#10B981" stop-opacity="0" />
            </radialGradient>
            <radialGradient id="hubGlowRed" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stop-color="#EF4444" stop-opacity="0.35" />
              <stop offset="100%" stop-color="#EF4444" stop-opacity="0" />
            </radialGradient>
          </defs>

          <!-- ==================== SANKEY RIBBONS LAYER ==================== -->
          <g class="sankey-ribbons-layer">
            <path
              v-for="ribbon in sankeyRibbons"
              :key="ribbon.id"
              data-testid="sankey-ribbon"
              :d="ribbon.d"
              fill="none"
              :stroke="ribbon.stroke"
              :stroke-width="ribbon.strokeWidth"
              :style="{
                opacity: ribbon.dimmed ? 0.15 : 1,
                cursor: 'pointer',
                transition: 'stroke 0.2s ease, opacity 0.3s ease, stroke-width 0.2s ease',
              }"
              @mouseenter="(e) => {
                hoveredRibbonId = ribbon.id
                handleShowTooltip(e, ribbon.tooltipHeader, ribbon.tooltipSubtext)
              }"
              @mouseleave="() => {
                hoveredRibbonId = null
                handleHideTooltip()
              }"
            />
          </g>

          <!-- ==================== COLUMN A: INGRESS SOURCES (x = 270) ==================== -->
          <g class="ingress-sources-column">
            <!-- 1. Top Cluster: Automated Bots (y = 200) -->
            <g
              data-testid="source-node-bots"
              class="cursor-pointer"
            >
              <!-- Concentric Dashed Rings -->
              <circle cx="270" cy="200" r="78" fill="none" stroke="#2E3644" stroke-dasharray="2 5" />
              <circle cx="270" cy="200" r="108" fill="none" stroke="#2E3644" stroke-dasharray="2 5" />

              <!-- Orbiting Perimeter Badges (4 badges along rings) -->
              <g
                class="orbit-badge cursor-pointer"
                @mouseenter="hoveredBadgeCluster = 'bots'"
                @mouseleave="hoveredBadgeCluster = null"
              >
                <!-- Badge 1: 45° r=108 -> (346.4, 276.4) -->
                <circle cx="346" cy="276" r="12" fill="#161A22" stroke="#2E3644" stroke-width="1.5" />
                <Bot class="w-3.5 h-3.5 text-[#848D9C]" x="339" y="269" width="14" height="14" />

                <!-- Badge 2: 135° r=108 -> (193.6, 276.4) -->
                <circle cx="194" cy="276" r="12" fill="#161A22" stroke="#2E3644" stroke-width="1.5" />
                <Lock class="w-3.5 h-3.5 text-[#848D9C]" x="187" y="269" width="14" height="14" />

                <!-- Badge 3: 225° r=78 -> (214.8, 144.8) -->
                <circle cx="215" cy="145" r="12" fill="#161A22" stroke="#2E3644" stroke-width="1.5" />
                <Globe class="w-3.5 h-3.5 text-[#848D9C]" x="208" y="138" width="14" height="14" />

                <!-- Badge 4: 315° r=78 -> (325.2, 144.8) -->
                <circle cx="325" cy="145" r="12" fill="#161A22" stroke="#2E3644" stroke-width="1.5" />
                <Smartphone class="w-3.5 h-3.5 text-[#848D9C]" x="318" y="138" width="14" height="14" />
              </g>

              <!-- Central Node Surface -->
              <circle cx="270" cy="200" r="52" fill="#11141A" stroke="#EF4444" stroke-width="1.5" />
              <!-- Text -->
              <text x="270" y="192" text-anchor="middle" fill="#FFFFFF" font-size="20" font-weight="bold" class="tabular-nums">48.2k</text>
              <text x="270" y="210" text-anchor="middle" fill="#B0B8C4" font-size="11" font-weight="600" letter-spacing="1">AUTOMATED BOTS</text>
              <text x="270" y="226" text-anchor="middle" fill="#848D9C" font-size="11">{{ botsSubtext }}</text>
            </g>

            <!-- 2. Middle Cluster: Human Clients (y = 460) with Drill-Down -->
            <g
              data-testid="source-node-humans"
              class="cursor-pointer"
              @click="toggleHumansExpanded"
            >
              <!-- Outer Dashed Rings -->
              <circle cx="270" cy="460" r="78" fill="none" stroke="#2E3644" stroke-dasharray="2 5" />
              <circle cx="270" cy="460" r="108" fill="none" stroke="#2E3644" stroke-dasharray="2 5" />

              <!-- Orbiting Badges -->
              <g
                class="orbit-badge cursor-pointer"
                @mouseenter="hoveredBadgeCluster = 'humans'"
                @mouseleave="hoveredBadgeCluster = null"
              >
                <circle cx="346" cy="536" r="12" fill="#161A22" stroke="#2E3644" stroke-width="1.5" />
                <Globe class="w-3.5 h-3.5 text-[#848D9C]" x="339" y="529" width="14" height="14" />

                <circle cx="194" cy="536" r="12" fill="#161A22" stroke="#2E3644" stroke-width="1.5" />
                <Smartphone class="w-3.5 h-3.5 text-[#848D9C]" x="187" y="529" width="14" height="14" />

                <circle cx="215" cy="405" r="12" fill="#161A22" stroke="#2E3644" stroke-width="1.5" />
                <Lock class="w-3.5 h-3.5 text-[#848D9C]" x="208" y="398" width="14" height="14" />

                <circle cx="325" cy="405" r="12" fill="#161A22" stroke="#2E3644" stroke-width="1.5" />
                <Bot class="w-3.5 h-3.5 text-[#848D9C]" x="318" y="398" width="14" height="14" />
              </g>

              <!-- Central Node Surface -->
              <circle cx="270" cy="460" r="52" fill="#11141A" stroke="#10B981" stroke-width="1.5" />
              <text x="270" y="450" text-anchor="middle" fill="#FFFFFF" font-size="20" font-weight="bold" class="tabular-nums">142.8k</text>
              <text x="270" y="468" text-anchor="middle" fill="#B0B8C4" font-size="11" font-weight="600" letter-spacing="1">HUMAN CLIENTS</text>
              <text x="270" y="484" text-anchor="middle" fill="#848D9C" font-size="11">{{ humansSubtext }}</text>

              <!-- Expand / Collapse Indicator -->
              <g transform="translate(263, 495)">
                <rect x="0" y="0" width="14" height="14" rx="7" :fill="isHumansExpanded ? '#2574F5' : '#1E232D'" :stroke="isHumansExpanded ? '#2574F5' : '#363D4C'" stroke-width="1" />
                <Minus v-if="isHumansExpanded" class="text-white" :size="10" :x="2" :y="2" />
                <ChevronDown v-else class="text-[#848D9C]" :size="10" :x="2" :y="2" />
              </g>
            </g>

            <!-- Expanded Sub-nodes when isHumansExpanded is true -->
            <g v-if="isHumansExpanded" class="humans-expansion-layer transition-opacity">
              <!-- Outer dotted expansion ring (r = 195) -->
              <circle cx="270" cy="460" r="195" fill="none" stroke="#2E3644" stroke-dasharray="2 5" />

              <!-- Connector Lines -->
              <path d="M 322 460 C 370 460, 390 345, 445 345" fill="none" stroke="#2E3644" stroke-dasharray="2 4" />
              <path d="M 322 460 C 370 460, 390 575, 445 575" fill="none" stroke="#2E3644" stroke-dasharray="2 4" />

              <!-- Sub-node 1: Verified Sessions at (445, 345) -->
              <g data-testid="subnode-verified" class="cursor-pointer">
                <circle cx="445" cy="345" r="44" fill="#161A22" stroke="#10B981" stroke-width="1.5" />
                <text x="445" y="338" text-anchor="middle" fill="#FFFFFF" font-size="15" font-weight="bold" class="tabular-nums">128.4k</text>
                <text x="445" y="352" text-anchor="middle" fill="#B0B8C4" font-size="10" font-weight="600" letter-spacing="0.5">VERIFIED SESSIONS</text>
                <text x="445" y="366" text-anchor="middle" fill="#848D9C" font-size="9.5">17.8M Reqs (JWT Valid)</text>

                <!-- Info Badge (i) -->
                <g transform="translate(474, 318)">
                  <circle r="8" fill="#2574F5" />
                  <Info class="w-2.5 h-2.5 text-white" x="-5" y="-5" width="10" height="10" />
                </g>
              </g>

              <!-- Sub-node 2: Anonymous / Proxy at (445, 575) -->
              <g data-testid="subnode-anonymous" class="cursor-pointer">
                <circle cx="445" cy="575" r="44" fill="#161A22" stroke="#F59E0B" stroke-width="1.5" />
                <text x="445" y="568" text-anchor="middle" fill="#FFFFFF" font-size="15" font-weight="bold" class="tabular-nums">14.4k</text>
                <text x="445" y="582" text-anchor="middle" fill="#B0B8C4" font-size="10" font-weight="600" letter-spacing="0.5">ANONYMOUS / PROXY</text>
                <text x="445" y="596" text-anchor="middle" fill="#848D9C" font-size="9.5">1.1M Reqs (Challenged)</text>
              </g>
            </g>

            <!-- 3. Bottom Cluster: API Consumers (y = 730) -->
            <g
              data-testid="source-node-api"
              class="cursor-pointer"
            >
              <!-- Outer Dashed Rings -->
              <circle cx="270" cy="730" r="78" fill="none" stroke="#2E3644" stroke-dasharray="2 5" />
              <circle cx="270" cy="730" r="108" fill="none" stroke="#2E3644" stroke-dasharray="2 5" />

              <!-- Orbiting Badges -->
              <g
                class="orbit-badge cursor-pointer"
                @mouseenter="hoveredBadgeCluster = 'api'"
                @mouseleave="hoveredBadgeCluster = null"
              >
                <circle cx="346" cy="806" r="12" fill="#161A22" stroke="#2E3644" stroke-width="1.5" />
                <Server class="w-3.5 h-3.5 text-[#848D9C]" x="339" y="799" width="14" height="14" />

                <circle cx="194" cy="806" r="12" fill="#161A22" stroke="#2E3644" stroke-width="1.5" />
                <Lock class="w-3.5 h-3.5 text-[#848D9C]" x="187" y="799" width="14" height="14" />

                <circle cx="215" cy="675" r="12" fill="#161A22" stroke="#2E3644" stroke-width="1.5" />
                <Globe class="w-3.5 h-3.5 text-[#848D9C]" x="208" y="668" width="14" height="14" />

                <circle cx="325" cy="675" r="12" fill="#161A22" stroke="#2E3644" stroke-width="1.5" />
                <Key class="w-3.5 h-3.5 text-[#848D9C]" x="318" y="668" width="14" height="14" />
              </g>

              <!-- Central Node Surface -->
              <circle cx="270" cy="730" r="52" fill="#11141A" stroke="#2574F5" stroke-width="1.5" />
              <text x="270" y="722" text-anchor="middle" fill="#FFFFFF" font-size="20" font-weight="bold" class="tabular-nums">12.1k</text>
              <text x="270" y="740" text-anchor="middle" fill="#B0B8C4" font-size="11" font-weight="600" letter-spacing="1">API CONSUMERS</text>
              <text x="270" y="756" text-anchor="middle" fill="#848D9C" font-size="11">{{ apiSubtext }}</text>
            </g>
          </g>

          <!-- ==================== COLUMN B: WAF HUBS (x = 800) ==================== -->
          <g class="waf-hubs-column">
            <!-- 1. Upper Hub: WAF Core Engine (y = 330) -->
            <g
              data-testid="hub-waf-core"
              class="cursor-pointer"
              :style="{
                transform: hoveredHubId === 'waf-core' ? 'scale(1.12)' : 'scale(1)',
                transformOrigin: '800px 330px',
                transformBox: 'view-box',
                transition: 'transform 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
              }"
              @mouseenter="hoveredHubId = 'waf-core'"
              @mouseleave="hoveredHubId = null"
            >
              <!-- 48 Radial Starburst Spikes -->
              <line
                v-for="(tick, idx) in wafCoreTicks"
                :key="idx"
                :x1="tick.x1"
                :y1="tick.y1"
                :x2="tick.x2"
                :y2="tick.y2"
                :stroke="tick.color"
                :stroke-width="tick.strokeWidth"
                stroke-linecap="round"
              />

              <!-- Hub Outer Shell -->
              <circle cx="800" cy="330" r="56" fill="#161A22" stroke="#363D4C" stroke-width="2" />
              <circle cx="800" cy="330" r="44" fill="#11141A" stroke="#10B981" stroke-width="1.5" stroke-opacity="0.8" />

              <!-- Hub Center Shield Icon -->
              <g transform="translate(788, 318)">
                <ShieldCheck class="w-6 h-6 text-[#10B981]" width="24" height="24" />
              </g>

              <!-- Hub Label & Telemetry -->
              <text x="800" y="440" text-anchor="middle" fill="#FFFFFF" font-size="13" font-weight="bold" letter-spacing="0.5">
                WAF CORE ENGINE
              </text>
              <text x="800" y="456" text-anchor="middle" fill="#848D9C" font-size="11">
                OWASP CRS v4 + 42 Custom Rules • 0.8ms p95
              </text>
            </g>

            <!-- 2. Lower Hub: Edge & Bot Defense (y = 600) -->
            <g
              data-testid="hub-edge-defense"
              class="cursor-pointer"
              :style="{
                transform: hoveredHubId === 'edge-defense' ? 'scale(1.12)' : 'scale(1)',
                transformOrigin: '800px 600px',
                transformBox: 'view-box',
                transition: 'transform 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
              }"
              @mouseenter="hoveredHubId = 'edge-defense'"
              @mouseleave="hoveredHubId = null"
            >
              <!-- 48 Radial Starburst Spikes -->
              <line
                v-for="(tick, idx) in edgeDefenseTicks"
                :key="idx"
                :x1="tick.x1"
                :y1="tick.y1"
                :x2="tick.x2"
                :y2="tick.y2"
                :stroke="tick.color"
                :stroke-width="tick.strokeWidth"
                stroke-linecap="round"
              />

              <!-- Hub Outer Shell -->
              <circle cx="800" cy="600" r="56" fill="#161A22" stroke="#363D4C" stroke-width="2" />
              <circle cx="800" cy="600" r="44" fill="#11141A" stroke="#2574F5" stroke-width="1.5" stroke-opacity="0.8" />

              <!-- Hub Center Icon -->
              <g transform="translate(788, 588)">
                <Bot class="w-6 h-6 text-[#2574F5]" width="24" height="24" />
              </g>

              <!-- Hub Label & Telemetry -->
              <text x="800" y="710" text-anchor="middle" fill="#FFFFFF" font-size="13" font-weight="bold" letter-spacing="0.5">
                EDGE & BOT DEFENSE
              </text>
              <text x="800" y="726" text-anchor="middle" fill="#848D9C" font-size="11">
                18 Rate Policies, Geo-IP & JA4 Fingerprinting
              </text>
            </g>
          </g>

          <!-- ==================== COLUMN C: DESTINATION & THREAT ARCS ==================== -->
          <g class="destination-arcs-column">
            <!-- Upper Arc (y = 330) -->
            <g class="upper-arc-group">
              <!-- Dotted Circular Arc -->
              <path
                d="M 1320 180 A 180 180 0 0 1 1370 330 A 180 180 0 0 1 1320 480"
                fill="none"
                stroke="#363D4C"
                stroke-dasharray="2 5"
                stroke-width="1.5"
              />

              <!-- Upper Summary Counter (x = 1190) -->
              <g data-testid="dest-summary-upper" class="cursor-default">
                <text x="1190" y="318" fill="#FFFFFF" font-size="28" font-weight="bold" class="tabular-nums">
                  {{ upperSummary.count }}
                </text>
                <text x="1190" y="338" fill="#B0B8C4" font-size="11" font-weight="600" letter-spacing="1">
                  {{ upperSummary.title }}
                </text>
                <text x="1190" y="354" fill="#848D9C" font-size="12">
                  {{ upperSummary.subtext }}
                </text>
              </g>

              <!-- Upper Arc Node Items -->
              <g
                v-for="item in upperArcNodes"
                :key="item.id"
                data-testid="arc-node-item"
                class="cursor-pointer group"
                @mouseenter="(e) => {
                  hoveredArcNodeId = item.id
                  handleShowTooltip(e, item.tooltipHeader, item.tooltipSubtext)
                }"
                @mouseleave="() => {
                  hoveredArcNodeId = null
                  handleHideTooltip()
                }"
              >
                <!-- Arc Connector Dot -->
                <circle
                  :cx="item.x"
                  :cy="item.y"
                  r="5"
                  :fill="item.isAttackTarget || viewMode === 'threats' ? '#EF4444' : '#10B981'"
                  stroke="#161A22"
                  stroke-width="1.5"
                />

                <!-- Route Pill / Label -->
                <g :transform="`translate(${item.x + 12}, ${item.y - 10})`">
                  <rect
                    x="0"
                    y="0"
                    :width="Math.max(item.label.length * 7 + (item.method ? 44 : 20), 80)"
                    height="20"
                    rx="4"
                    fill="#1E222A"
                    stroke="#363D4C"
                    stroke-width="1"
                    class="transition-colors group-hover:stroke-[#60A5FA]"
                  />
                  <!-- Optional Method Tag -->
                  <text
                    v-if="item.method"
                    x="6"
                    y="14"
                    :fill="item.method === 'POST' ? '#60A5FA' : '#10B981'"
                    font-size="9"
                    font-weight="bold"
                  >
                    {{ item.method }}
                  </text>
                  <text
                    :x="item.method ? 38 : 8"
                    y="14"
                    fill="#FFFFFF"
                    font-size="10.5"
                    font-family="monospace"
                  >
                    {{ item.label }}
                  </text>
                </g>
              </g>
            </g>

            <!-- Lower Arc (y = 600) with Opacity Dimming when owaspOnly === true -->
            <g
              class="lower-arc-group transition-opacity duration-300"
              :style="{ opacity: (owaspOnly && viewMode === 'traffic') ? 0.15 : 1 }"
            >
              <!-- Dotted Circular Arc -->
              <path
                d="M 1320 450 A 180 180 0 0 1 1370 600 A 180 180 0 0 1 1320 750"
                fill="none"
                stroke="#363D4C"
                stroke-dasharray="2 5"
                stroke-width="1.5"
              />

              <!-- Lower Summary Counter (x = 1190) -->
              <g data-testid="dest-summary-lower" class="cursor-default">
                <text x="1190" y="588" fill="#FFFFFF" font-size="28" font-weight="bold" class="tabular-nums">
                  {{ lowerSummary.count }}
                </text>
                <text x="1190" y="608" fill="#B0B8C4" font-size="11" font-weight="600" letter-spacing="1">
                  {{ lowerSummary.title }}
                </text>
                <text x="1190" y="624" fill="#848D9C" font-size="12">
                  {{ lowerSummary.subtext }}
                </text>
              </g>

              <!-- Lower Arc Node Items -->
              <g
                v-for="item in lowerArcNodes"
                :key="item.id"
                data-testid="arc-node-item"
                class="cursor-pointer group"
                @mouseenter="(e) => {
                  hoveredArcNodeId = item.id
                  handleShowTooltip(e, item.tooltipHeader, item.tooltipSubtext)
                }"
                @mouseleave="() => {
                  hoveredArcNodeId = null
                  handleHideTooltip()
                }"
              >
                <!-- Arc Connector Dot -->
                <circle
                  :cx="item.x"
                  :cy="item.y"
                  r="5"
                  :fill="viewMode === 'threats' ? '#EF4444' : '#10B981'"
                  stroke="#161A22"
                  stroke-width="1.5"
                />

                <!-- Route Pill / Label -->
                <g :transform="`translate(${item.x + 12}, ${item.y - 10})`">
                  <rect
                    x="0"
                    y="0"
                    :width="Math.max(item.label.length * 7 + (item.method ? 44 : 20), 80)"
                    height="20"
                    rx="4"
                    fill="#1E222A"
                    stroke="#363D4C"
                    stroke-width="1"
                    class="transition-colors group-hover:stroke-[#60A5FA]"
                  />
                  <!-- Optional Method Tag -->
                  <text
                    v-if="item.method"
                    x="6"
                    y="14"
                    :fill="item.method === 'POST' ? '#60A5FA' : '#10B981'"
                    font-size="9"
                    font-weight="bold"
                  >
                    {{ item.method }}
                  </text>
                  <text
                    :x="item.method ? 38 : 8"
                    y="14"
                    fill="#FFFFFF"
                    font-size="10.5"
                    font-family="monospace"
                  >
                    {{ item.label }}
                  </text>
                </g>
              </g>
            </g>
          </g>
        </svg>
      </div>

      <!-- Floating Contextual Tooltip -->
      <div
        v-if="tooltip.visible"
        data-testid="topology-tooltip"
        class="fixed w-[275px] bg-[#222731] border border-[#3E4656] rounded-md p-3.5 shadow-2xl pointer-events-none z-50 transition-all duration-75"
        :style="{
          left: `${tooltip.x}px`,
          top: `${tooltip.y}px`,
        }"
      >
        <div class="text-[13px] font-bold text-white leading-snug">
          {{ tooltip.header }}
        </div>
        <div class="border-t border-[#363D4C] my-2"></div>
        <div class="text-[12px] text-[#B0B8C4] leading-relaxed">
          {{ tooltip.subtext }}
        </div>
      </div>
    </main>
  </div>
</template>

<style scoped>
/* Prevent any scroll or layout jumping */
:host {
  display: block;
  overflow: hidden;
}
</style>
