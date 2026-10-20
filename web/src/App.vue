<script setup lang="ts">
import { computed } from 'vue';
import { useRoute } from '@/router';
import DashboardLayout from '@/layouts/DashboardLayout.vue';
import LoginView from '@/views/LoginView.vue';
import { TooltipProvider } from '@/components/ui/tooltip';

const route = useRoute();
const isLoginPage = computed(() => route.value.path === '/login');
</script>

<template>
  <TooltipProvider>
    <LoginView v-if="isLoginPage" />
    <DashboardLayout v-else>
      <RouterView />
    </DashboardLayout>
  </TooltipProvider>
</template>
