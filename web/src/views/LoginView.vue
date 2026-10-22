<script setup lang="ts">
import { ref } from 'vue';
import { useAuthStore } from '@/stores/auth';
import { useRouter } from '@/router';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Lock, User, AlertCircle, Sun, Moon } from 'lucide-vue-next';
import { useTheme } from '@/composables/useTheme';

const authStore = useAuthStore();
const router = useRouter();
const { isDark, toggleTheme } = useTheme();

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
  <div class="min-h-screen bg-background flex flex-col items-center justify-center p-4 font-sans text-foreground relative">
    <!-- Top-Right Theme Toggle -->
    <div class="absolute top-4 right-4">
      <button
        data-testid="login-theme-toggle-btn"
        type="button"
        @click="toggleTheme"
        class="flex items-center justify-center w-8 h-8 rounded-full border border-border bg-card text-foreground hover:bg-muted transition-colors cursor-pointer"
        :title="isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'"
        :aria-label="isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'"
      >
        <Sun v-if="isDark" class="w-4 h-4 text-warning" />
        <Moon v-else class="w-4 h-4 text-primary" />
      </button>
    </div>

    <div class="w-full max-w-md bg-card border border-border rounded-xl p-8 shadow-none">
      <div class="flex items-center justify-center space-x-3 mb-6">
        <img
          src="/logo.png"
          alt="Raiwall Logo"
          class="w-10 h-10 object-contain"
          style="image-rendering: -webkit-optimize-contrast;"
        />
        <h1 class="text-xl font-bold tracking-tight text-foreground font-sans">Raiwall Control Plane</h1>
      </div>

      <p class="text-xs text-muted-foreground text-center mb-6">
        Sign in with your administrative or auditor credentials to manage gateway WAF configurations.
      </p>

      <div v-if="errorMessage" class="mb-4 p-3 bg-threat/10 border border-threat/30 rounded-lg flex items-center space-x-3 text-threat text-xs">
        <AlertCircle class="w-4 h-4 flex-shrink-0 text-muted-foreground" />
        <span>{{ errorMessage }}</span>
      </div>

      <form @submit.prevent="handleLogin" class="space-y-4">
        <div>
          <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Username</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 pl-3 flex items-center text-muted-foreground">
              <User class="w-4 h-4" />
            </span>
            <Input
              v-model="username"
              type="text"
              required
              class="pl-10"
              placeholder="Username"
            />
          </div>
        </div>

        <div>
          <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Password</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 pl-3 flex items-center text-muted-foreground">
              <Lock class="w-4 h-4" />
            </span>
            <Input
              v-model="password"
              type="password"
              required
              class="pl-10"
              placeholder="••••••••"
            />
          </div>
        </div>

        <Button
          type="submit"
          :disabled="loading"
          class="w-full h-10 text-sm font-medium mt-2"
        >
          <span v-if="loading">Signing in...</span>
          <span v-else>Sign In</span>
        </Button>
      </form>
    </div>
  </div>
</template>
