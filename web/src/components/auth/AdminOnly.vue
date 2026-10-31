<script setup lang="ts">
import { computed } from 'vue';
import { useAuthStore } from '@/stores/auth';

/**
 * Renders its slot unless the signed-in principal is explicitly a viewer.
 * Backend RBAC remains authoritative; this only avoids showing write actions
 * that would return 403.
 */
const auth = useAuthStore();
const allowed = computed(() => auth.user?.role !== 'viewer');
</script>

<template>
  <slot v-if="allowed" />
</template>
