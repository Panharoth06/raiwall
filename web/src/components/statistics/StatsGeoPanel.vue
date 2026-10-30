<script setup lang="ts">
import { ref, computed } from 'vue'
import { Check, Copy, Globe } from 'lucide-vue-next'
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { EmptyState } from '@/components/ui/empty-state'
import { countryCoords } from './geoData'
import GlobeCdn from '@/components/GlobeCdn.vue'
import AttackMap2D from './AttackMap2D.vue'
import { type CdnMarker, type CdnArc } from '@/components/cobeDefaults'
import type { GeoIPStatus, TopCount } from '@/types/telemetry'

const props = defineProps<{
  countries: TopCount[]
  selectedCountry?: string
  totalRequests: number
  totalBlocked: number
  geoip?: GeoIPStatus | null
}>()

const emit = defineEmits<{
  (e: 'selectCountry', country: string): void
}>()

const viewMode = ref<'3d' | '2d'>('3d')
const dataMode = ref<'requests' | 'blocked'>('requests')
const setupCopied = ref(false)

const geoipDisabled = computed(() => props.geoip != null && !props.geoip.country_db)

const geoipSetupSnippet = `export RAIWALL_GEOIP_LICENSE_KEY=<maxmind-license-key>

# config/raiwall.yaml
geoip:
  country: /usr/share/GeoIP/GeoLite2-Country.mmdb
  city: /usr/share/GeoIP/GeoLite2-City.mmdb
  asn: /usr/share/GeoIP/GeoLite2-ASN.mmdb
  auto_update: true`

async function copyGeoIPSetup() {
  try {
    await navigator.clipboard.writeText(geoipSetupSnippet)
    setupCopied.value = true
    window.setTimeout(() => { setupCopied.value = false }, 2000)
  } catch {
    setupCopied.value = false
  }
}

const maxCountryCount = computed(() => {
  let max = 1
  for (const c of props.countries) {
    if (c.count > max) max = c.count
  }
  return max
})

// Dynamic Markers generated strictly from real telemetry country hits for 3D Globe - zero mock defaults
const dynamicMarkers = computed<CdnMarker[]>(() => {
  if (!props.countries || props.countries.length === 0) {
    return []
  }

  return props.countries
    .slice(0, 10)
    .map((c) => {
      const coord = countryCoords[c.key]
      if (!coord) return null
      const id = `country-${c.key.toLowerCase().replace(/[^a-z0-9]/g, '-')}`
      const regionName = c.key.length > 8 ? c.key.slice(0, 7) + '.' : c.key
      return {
        id,
        location: [coord.lat, coord.lon] as [number, number],
        region: regionName,
      }
    })
    .filter((m): m is CdnMarker => m !== null)
})

const dynamicArcs = computed<CdnArc[]>(() => {
  // Zero mock arcs: only real telemetry data is visualized
  return []
})

function formatCount(num: number): string {
  if (num >= 1_000_000) return (num / 1_000_000).toFixed(1) + 'M'
  if (num >= 1_000) return (num / 1_000).toFixed(1) + 'k'
  return num.toLocaleString()
}
</script>

<template>
  <Card class="flex flex-col justify-between">
    <CardHeader class="pb-3">
      <!-- Header with Toggles -->
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-2">
          <div class="w-7 h-7 rounded-md bg-primary/10 text-primary flex items-center justify-center">
            <Globe class="w-4 h-4" />
          </div>
          <CardTitle class="text-base font-semibold text-foreground tracking-tight">
            Geo Location
          </CardTitle>
          <span
            v-if="geoipDisabled"
            data-testid="geoip-disabled-badge"
            class="text-xs font-mono px-1.5 py-0.5 rounded border border-warning/40 bg-warning/10 text-warning"
          >
            GEOIP OFF
          </span>
        </div>

        <div class="flex items-center gap-2">
          <!-- 3D / 2D Toggle -->
          <div class="inline-flex items-center rounded-lg border border-border p-0.5 bg-muted/40">
            <Button
              type="button"
              size="sm"
              data-testid="toggle-3d"
              :variant="viewMode === '3d' ? 'default' : 'ghost'"
              class="h-6 px-2 text-xs font-mono shadow-none"
              @click="viewMode = '3d'"
            >
              3D
            </Button>
            <Button
              type="button"
              size="sm"
              data-testid="toggle-2d"
              :variant="viewMode === '2d' ? 'default' : 'ghost'"
              class="h-6 px-2 text-xs font-mono shadow-none"
              @click="viewMode = '2d'"
            >
              2D
            </Button>
          </div>

          <!-- Requests / Blocked Filter Toggle -->
          <div class="inline-flex items-center rounded-lg border border-border p-0.5 bg-muted/40">
            <Button
              type="button"
              size="sm"
              data-testid="toggle-requests-mode"
              :variant="dataMode === 'requests' ? 'default' : 'ghost'"
              class="h-6 px-2.5 text-xs font-mono shadow-none"
              @click="dataMode = 'requests'"
            >
              REQUESTS
            </Button>
            <Button
              type="button"
              size="sm"
              data-testid="toggle-blocked-mode"
              :variant="dataMode === 'blocked' ? 'destructive' : 'ghost'"
              class="h-6 px-2.5 text-xs font-mono shadow-none"
              @click="dataMode = 'blocked'"
            >
              BLOCKED
            </Button>
          </div>
        </div>
      </div>
    </CardHeader>

    <CardContent class="pt-0">
      <!-- Main Content: Globe/Map (Left) + Country Leaderboard (Right) -->
      <div class="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        <div class="md:col-span-7 flex items-center justify-center relative min-h-[320px]">
          <!-- 3D Dynamic Cobe Globe -->
          <GlobeCdn
            v-if="viewMode === '3d'"
            :markers="dynamicMarkers"
            :arcs="dynamicArcs"
            class="w-full max-w-[340px] aspect-square"
          />

          <!-- 2D Apache ECharts Attack Flow Map -->
          <AttackMap2D
            v-else
            :countries="countries"
            :selected-country="selectedCountry"
            :data-mode="dataMode"
            @select-country="emit('selectCountry', $event)"
          />
        </div>

        <!-- Country Distribution List -->
        <div class="md:col-span-5 space-y-2.5 max-h-[320px] overflow-y-auto pr-1">
          <div
            v-for="(country, idx) in countries"
            :key="country.key"
            data-testid="country-row"
            @click="emit('selectCountry', country.key)"
            :class="[
              'p-2 rounded-lg border transition-all cursor-pointer flex flex-col gap-1.5',
              selectedCountry === country.key
                ? 'bg-primary/10 border-primary/40 text-foreground'
                : 'bg-muted/30 border-transparent hover:border-border hover:bg-muted/60',
            ]"
          >
            <div class="flex items-center justify-between text-xs font-mono">
              <span class="flex items-center gap-1.5 font-semibold">
                <span class="text-muted-foreground text-xs">#{{ idx + 1 }}</span>
                <span class="truncate max-w-[120px]">{{ country.key }}</span>
                <Check v-if="selectedCountry === country.key" class="w-3.5 h-3.5 text-primary ml-1" />
              </span>
              <span class="font-bold tabular-nums">
                {{ formatCount(country.count) }}
              </span>
            </div>
            <Progress
              :model-value="maxCountryCount > 0 ? (country.count / maxCountryCount) * 100 : 0"
              :max="100"
              :variant="dataMode === 'blocked' ? 'threat' : 'primary'"
              class="h-1.5"
            />
          </div>

          <!-- Empty state: GeoIP disabled is a configuration gap, not an empty window -->
          <EmptyState
            v-if="countries.length === 0 && geoipDisabled"
            data-testid="geoip-disabled-empty"
            :icon="Globe"
            title="GeoIP lookup is disabled"
            description="No MaxMind database is loaded, so every event is recorded without a country. Mount GeoLite2-Country.mmdb or enable auto-download with a licence key, then restart the gateway."
            class="py-6 pt-4"
          >
            <Button size="sm" variant="outline" class="h-7 text-xs font-mono" @click="copyGeoIPSetup">
              <Check v-if="setupCopied" class="w-3.5 h-3.5 text-success" />
              <Copy v-else class="w-3.5 h-3.5" />
              {{ setupCopied ? 'Copied' : 'Copy setup' }}
            </Button>
          </EmptyState>

          <!-- Empty state: geo enrichment is active but no public IP was seen -->
          <EmptyState
            v-else-if="countries.length === 0"
            :icon="Globe"
            title="No geo distribution events recorded"
            description="No public client IP was recorded for this time frame. Private and loopback addresses are never geolocated — behind a proxy set proxy.client_ip_source so the real address is inspected."
            class="py-6 pt-4"
          />
        </div>
      </div>
    </CardContent>
  </Card>
</template>
