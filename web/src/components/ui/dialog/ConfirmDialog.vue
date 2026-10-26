<script setup lang="ts">
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'

const props = withDefaults(
  defineProps<{
    open: boolean
    title: string
    description?: string
    confirmText?: string
    cancelText?: string
    variant?: 'default' | 'destructive'
    loading?: boolean
  }>(),
  {
    description: '',
    confirmText: 'Confirm',
    cancelText: 'Cancel',
    variant: 'default',
    loading: false,
  }
)

const emit = defineEmits<{
  (e: 'update:open', val: boolean): void
  (e: 'confirm'): void
  (e: 'cancel'): void
}>()

function onConfirm() {
  emit('confirm')
}

function onCancel() {
  emit('cancel')
  emit('update:open', false)
}
</script>

<template>
  <Dialog :open="open" @update:open="emit('update:open', $event)">
    <DialogContent class="sm:max-w-md bg-card border-border">
      <DialogHeader>
        <DialogTitle class="text-base font-semibold text-foreground">
          {{ title }}
        </DialogTitle>
        <DialogDescription v-if="description" class="text-sm text-muted-foreground mt-1">
          {{ description }}
        </DialogDescription>
      </DialogHeader>

      <DialogFooter class="flex sm:justify-end gap-2 pt-4">
        <Button
          type="button"
          variant="outline"
          size="sm"
          :disabled="loading"
          @click="onCancel"
        >
          {{ cancelText }}
        </Button>
        <Button
          type="button"
          :variant="variant === 'destructive' ? 'destructive' : 'default'"
          size="sm"
          :disabled="loading"
          @click="onConfirm"
        >
          <span v-if="loading" class="animate-spin mr-1.5">⏳</span>
          {{ confirmText }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
