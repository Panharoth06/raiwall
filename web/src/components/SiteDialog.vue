<script setup lang="ts">
import { ref, watch } from 'vue';
import type { Site, Upstream } from '@/api/client';
import UpstreamPoolEditor from './UpstreamPoolEditor.vue';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { Globe, Save } from 'lucide-vue-next';

const props = defineProps<{
  open: boolean;
  site?: Site | null;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'save', site: Partial<Site>): void;
}>();

const formName = ref('');
const formHostnames = ref('');
const formMode = ref<'defense' | 'audit' | 'offline'>('defense');
const formUpstreams = ref<Upstream[]>([]);
const formBlockCode = ref(403);
const formOfflineCode = ref(503);

watch(
  () => props.site,
  (val) => {
    if (val) {
      formName.value = val.name || '';
      formHostnames.value = (val.hostnames || []).join(', ');
      formMode.value = val.mode || 'defense';
      formUpstreams.value = JSON.parse(JSON.stringify(val.upstreams || []));
      formBlockCode.value = val.block_status_code || 403;
      formOfflineCode.value = val.offline_status_code || 503;
    } else {
      formName.value = '';
      formHostnames.value = '';
      formMode.value = 'defense';
      formUpstreams.value = [];
      formBlockCode.value = 403;
      formOfflineCode.value = 503;
    }
  },
  { immediate: true }
);

const handleSave = () => {
  const hosts = formHostnames.value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  emit('save', {
    id: props.site?.id,
    name: formName.value,
    hostnames: hosts,
    mode: formMode.value,
    upstreams: formUpstreams.value,
    block_status_code: formBlockCode.value,
    offline_status_code: formOfflineCode.value,
  });
  emit('close');
};

const handleOpenChange = (openState: boolean) => {
  if (!openState) {
    emit('close');
  }
};
</script>

<template>
  <Dialog :open="open" @update:open="handleOpenChange">
    <DialogContent class="max-w-2xl bg-[#1e222a] border-[#2d3440] p-6 max-h-[90vh] flex flex-col font-sans">
      <!-- Header -->
      <DialogHeader>
        <div class="flex items-center space-x-2.5">
          <Globe class="w-5 h-5 text-slate-400" />
          <DialogTitle>
            {{ site ? 'Edit Protected Site' : 'Add Protected Site' }}
          </DialogTitle>
        </div>
      </DialogHeader>

      <!-- Body -->
      <div class="py-2 overflow-y-auto space-y-4 flex-1">
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Site Name</label>
            <Input
              v-model="formName"
              placeholder="e.g. Payment Gateway"
            />
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Operational Mode</label>
            <Select v-model="formMode">
              <SelectTrigger class="w-full h-9 border-[#363D4C] bg-[#15181F] text-xs text-white">
                <SelectValue />
              </SelectTrigger>
              <SelectContent class="border-[#363D4C] bg-[#1E222A] text-white">
                <SelectItem value="defense">Defense (Active Threat Blocking)</SelectItem>
                <SelectItem value="audit">Audit (Log & Alert Only)</SelectItem>
                <SelectItem value="offline">Offline (Maintenance 503)</SelectItem>
              </SelectContent>
            </Select>
            <select v-model="formMode" class="sr-only" tabindex="-1" aria-hidden="true">
              <option value="defense">Defense</option>
              <option value="audit">Audit</option>
              <option value="offline">Offline</option>
            </select>
          </div>
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
            Hostnames (comma separated)
          </label>
          <Input
            v-model="formHostnames"
            placeholder="api.example.com, pay.example.com"
          />
        </div>

        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Block HTTP Status</label>
            <Input
              v-model.number="formBlockCode"
              type="number"
            />
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Offline HTTP Status</label>
            <Input
              v-model.number="formOfflineCode"
              type="number"
            />
          </div>
        </div>

        <div class="pt-2 border-t border-[#2d3440]">
          <UpstreamPoolEditor v-model="formUpstreams" />
        </div>
      </div>

      <!-- Footer -->
      <DialogFooter class="flex justify-end space-x-2 pt-4 border-t border-[#2d3440]">
        <Button
          type="button"
          variant="secondary"
          @click="$emit('close')"
        >
          Cancel
        </Button>
        <Button
          type="button"
          @click="handleSave"
          class="gap-1.5"
        >
          <Save class="w-3.5 h-3.5" />
          <span>Save to Draft</span>
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
