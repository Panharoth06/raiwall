<script setup lang="ts">
import { ref } from 'vue';
import { useAuthStore } from '@/stores/auth';
import { useRouter } from '@/router';
import { ShieldCheck, Lock, User, AlertCircle } from 'lucide-vue-next';

const authStore = useAuthStore();
const router = useRouter();

const username = ref('admin');
const password = ref('');
const errorMessage = ref('');
const loading = ref(false);

const handleLogin = async () => {
  if (!username.value || !password.value) {
    errorMessage.value = 'Please provide both username and password';
    return;
  }
  loading.value = true;
  errorMessage.value = '';

  const success = await authStore.login(username.value, password.value);
  loading.value = false;

  if (success) {
    await router.push('/');
  } else {
    errorMessage.value = authStore.error || 'Invalid credentials';
  }
};
</script>

<template>
  <div class="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-4">
    <div class="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-2xl">
      <div class="flex items-center justify-center space-x-3 mb-6">
        <div class="h-10 w-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
          <ShieldCheck class="w-6 h-6" />
        </div>
        <h1 class="text-2xl font-bold tracking-tight text-white">Raiwall Control Plane</h1>
      </div>

      <p class="text-sm text-slate-400 text-center mb-6">
        Sign in with your administrative or auditor credentials to manage gateway WAF configurations.
      </p>

      <div v-if="errorMessage" class="mb-4 p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg flex items-center space-x-3 text-rose-400 text-sm">
        <AlertCircle class="w-5 h-5 flex-shrink-0" />
        <span>{{ errorMessage }}</span>
      </div>

      <form @submit.prevent="handleLogin" class="space-y-4">
        <div>
          <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Username</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
              <User class="w-4 h-4" />
            </span>
            <input
              v-model="username"
              type="text"
              required
              class="w-full pl-10 pr-3 py-2 bg-slate-800/80 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 text-sm"
              placeholder="Username"
            />
          </div>
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Password</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
              <Lock class="w-4 h-4" />
            </span>
            <input
              v-model="password"
              type="password"
              required
              class="w-full pl-10 pr-3 py-2 bg-slate-800/80 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 text-sm"
              placeholder="••••••••"
            />
          </div>
        </div>

        <button
          type="submit"
          :disabled="loading"
          class="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded-lg text-sm transition-colors duration-150 flex items-center justify-center space-x-2 disabled:opacity-50"
        >
          <span v-if="loading">Signing in...</span>
          <span v-else>Sign In</span>
        </button>
      </form>
    </div>
  </div>
</template>
