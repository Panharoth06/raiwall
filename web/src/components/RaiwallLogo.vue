<script setup lang="ts">
withDefaults(
  defineProps<{
    size?: number | string;
    showText?: boolean;
    className?: string;
  }>(),
  {
    size: 32,
    showText: false,
    className: '',
  }
);
</script>

<template>
  <div class="inline-flex items-center gap-2.5 select-none" :class="className">
    <svg
      :width="size"
      :height="size"
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="Raiwall Logo"
      class="flex-shrink-0"
    >
      <defs>
        <!-- Outer Rim Gradient -->
        <linearGradient id="rw-shield-rim" x1="10" y1="5" x2="90" y2="95" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stop-color="#38BDF8" />
          <stop offset="45%" stop-color="#2574F5" />
          <stop offset="100%" stop-color="#0284C7" />
        </linearGradient>

        <!-- Shield Interior Gradient -->
        <radialGradient id="rw-shield-bg" cx="50" cy="30" r="55" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stop-color="#14244B" />
          <stop offset="65%" stop-color="#0D162B" />
          <stop offset="100%" stop-color="#070C18" />
        </radialGradient>

        <!-- Mascot Cyan Gradient -->
        <linearGradient id="rw-mascot-grad" x1="30" y1="15" x2="70" y2="52" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stop-color="#38E1FF" />
          <stop offset="100%" stop-color="#00A3FF" />
        </linearGradient>

        <!-- Shield Inner Clip -->
        <clipPath id="rw-shield-clip">
          <path d="M 50 6 C 73 6 88 12 88 28 C 88 60 62 82 50 94 C 38 82 12 60 12 28 C 12 12 27 6 50 6 Z" />
        </clipPath>
      </defs>

      <!-- Outer Shield Base & Rim -->
      <path
        d="M 50 4 C 75 4 91 10 91 28 C 91 62 63 85 50 98 C 37 85 9 62 9 28 C 9 10 25 4 50 4 Z"
        fill="#070C18"
        stroke="url(#rw-shield-rim)"
        stroke-width="3.5"
        stroke-linejoin="round"
      />

      <!-- Clipped Shield Interior -->
      <g clip-path="url(#rw-shield-clip)">
        <!-- Interior Dark Background -->
        <rect width="100" height="100" fill="url(#rw-shield-bg)" />

        <!-- Side Antenna / Gateway Nodes -->
        <line x1="22" y1="26" x2="22" y2="48" stroke="#38BDF8" stroke-width="1.8" stroke-linecap="round" opacity="0.85" />
        <line x1="18" y1="32" x2="26" y2="32" stroke="#38BDF8" stroke-width="1.8" stroke-linecap="round" opacity="0.85" />
        <line x1="18" y1="40" x2="26" y2="40" stroke="#38BDF8" stroke-width="1.8" stroke-linecap="round" opacity="0.85" />

        <line x1="78" y1="26" x2="78" y2="48" stroke="#38BDF8" stroke-width="1.8" stroke-linecap="round" opacity="0.85" />
        <line x1="74" y1="32" x2="82" y2="32" stroke="#38BDF8" stroke-width="1.8" stroke-linecap="round" opacity="0.85" />
        <line x1="74" y1="40" x2="82" y2="40" stroke="#38BDF8" stroke-width="1.8" stroke-linecap="round" opacity="0.85" />

        <!-- Mascot (Gopher Ears) -->
        <circle cx="34" cy="20" r="7.5" fill="url(#rw-mascot-grad)" stroke="#070C18" stroke-width="2" />
        <circle cx="34" cy="20" r="3.8" fill="#070C18" />
        <circle cx="66" cy="20" r="7.5" fill="url(#rw-mascot-grad)" stroke="#070C18" stroke-width="2" />
        <circle cx="66" cy="20" r="3.8" fill="#070C18" />

        <!-- Mascot Head & Body -->
        <path
          d="M 31 48 C 29 25 35 15 50 15 C 65 15 71 25 69 48 Z"
          fill="url(#rw-mascot-grad)"
          stroke="#070C18"
          stroke-width="2.2"
        />

        <!-- Eyes -->
        <ellipse cx="42" cy="28" rx="6.5" ry="8" fill="#FFFFFF" stroke="#070C18" stroke-width="2" />
        <ellipse cx="43" cy="28" rx="3.5" ry="4.2" fill="#070C18" />
        <circle cx="41.5" cy="26" r="1.4" fill="#FFFFFF" />

        <ellipse cx="58" cy="28" rx="6.5" ry="8" fill="#FFFFFF" stroke="#070C18" stroke-width="2" />
        <ellipse cx="57" cy="28" rx="3.5" ry="4.2" fill="#070C18" />
        <circle cx="55.5" cy="26" r="1.4" fill="#FFFFFF" />

        <!-- Snout & Tooth -->
        <ellipse cx="50" cy="36" rx="6" ry="4" fill="#00D2FF" />
        <ellipse cx="50" cy="34" rx="2.4" ry="1.6" fill="#070C18" />
        <path d="M 48 37 C 48 38.5 52 38.5 52 37" stroke="#070C18" stroke-width="1.4" stroke-linecap="round" />
        <rect x="48.7" y="37.8" width="2.6" height="2.6" rx="0.6" fill="#FFFFFF" stroke="#070C18" stroke-width="0.8" />

        <!-- Belly Light Patch -->
        <path d="M 37 48 C 37 43 63 43 63 48 Z" fill="#BAE6FD" opacity="0.9" />

        <!-- Crenelated Castle Wall / Firewall (Middle) -->
        <path
          d="M 12 51 
             L 24 51 L 24 46 L 32 46 L 32 51 
             L 44 51 L 44 46 L 56 46 L 56 51 
             L 68 51 L 68 46 L 76 46 L 76 51 
             L 88 51 
             L 88 58 L 12 58 Z"
          fill="#BAE6FD"
          stroke="#070C18"
          stroke-width="1.8"
        />

        <!-- Brick Wall Lower Section -->
        <path
          d="M 12 58 L 88 58 L 88 80 C 76 88 62 94 50 97 C 38 94 24 88 12 80 Z"
          fill="#0284C7"
        />

        <!-- Wall Horizontal Mortar Lines -->
        <line x1="12" y1="65" x2="88" y2="65" stroke="#070C18" stroke-width="1.8" />
        <line x1="16" y1="73" x2="84" y2="73" stroke="#070C18" stroke-width="1.8" />
        <line x1="24" y1="81" x2="76" y2="81" stroke="#070C18" stroke-width="1.8" />

        <!-- Vertical Mortar Lines -->
        <line x1="32" y1="58" x2="32" y2="65" stroke="#070C18" stroke-width="1.8" />
        <line x1="52" y1="58" x2="52" y2="65" stroke="#070C18" stroke-width="1.8" />
        <line x1="72" y1="58" x2="72" y2="65" stroke="#070C18" stroke-width="1.8" />

        <line x1="42" y1="65" x2="42" y2="73" stroke="#070C18" stroke-width="1.8" />
        <line x1="62" y1="65" x2="62" y2="73" stroke="#070C18" stroke-width="1.8" />

        <line x1="34" y1="73" x2="34" y2="81" stroke="#070C18" stroke-width="1.8" />
        <line x1="54" y1="73" x2="54" y2="81" stroke="#070C18" stroke-width="1.8" />
        <line x1="70" y1="73" x2="70" y2="81" stroke="#070C18" stroke-width="1.8" />

        <!-- Glowing Circuit Traces on Wall (Nodes & Paths) -->
        <path
          d="M 52 61 H 73 V 69 H 63 V 77 H 53 V 85"
          fill="none"
          stroke="#FFFFFF"
          stroke-width="1.8"
          stroke-linejoin="round"
          stroke-linecap="round"
        />
        <circle cx="52" cy="61" r="2.2" fill="#FFFFFF" />
        <circle cx="73" cy="69" r="2.2" fill="#FFFFFF" />
        <circle cx="53" cy="77" r="2.2" fill="#FFFFFF" />
        <circle cx="53" cy="85" r="2.2" fill="#FFFFFF" />

        <!-- Rim Corner Highlight -->
        <path
          d="M 50 96 C 58 87 72 79 84 69"
          fill="none"
          stroke="#38BDF8"
          stroke-width="1.8"
          stroke-linecap="round"
          opacity="0.75"
        />
      </g>
    </svg>

    <div v-if="showText" class="flex flex-col justify-center">
      <span class="font-bold text-white text-base tracking-tight leading-none">Raiwall</span>
    </div>
  </div>
</template>
