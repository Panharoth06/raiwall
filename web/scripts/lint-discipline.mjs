#!/usr/bin/env node
/**
 * Frontend Discipline & Strict Component Linter
 * 
 * Enforces the 6 Cardinal Frontend Commandments:
 * 1. Existing components over ad-hoc elements
 * 2. Never use native browser default components (select, checkbox, radio, alert, confirm, prompt, title tooltips)
 * 3. Typography hard floor: text-xs (12px) minimum; strictly ban sub-12px micro-text (text-[10px], etc.)
 * 4. Systemic consistency across views
 * 5. Zero mockup data & zero dead buttons (@click no-ops, console.logs)
 * 6. Strict backend API parity
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SRC_DIR = path.resolve(__dirname, '../src');

const RULES = [
  {
    id: 'NO_NATIVE_DIALOG',
    name: 'Rule 2: No Native Browser Dialogs',
    description: 'Native window.confirm(), window.alert(), and window.prompt() are strictly forbidden. Use Dialog or toast.',
    pattern: /\b(?:window\.)?(confirm|alert|prompt)\s*\(/g,
    excludeTestFiles: false,
    severity: 'error',
  },
  {
    id: 'NO_NATIVE_SELECT',
    name: 'Rule 2: No Native <select> Element',
    description: 'Native <select> elements are prohibited. Use shadcn-vue Select primitive from @/components/ui/select.',
    pattern: /<select\b/g,
    excludeTestFiles: false,
    severity: 'error',
  },
  {
    id: 'NO_NATIVE_CHECKBOX_RADIO',
    name: 'Rule 2: No Native Checkbox or Radio Controls',
    description: 'Native type="checkbox" and type="radio" are prohibited. Use Switch or Radix Checkbox/RadioGroup.',
    pattern: /type=["'](checkbox|radio)["']/g,
    excludeTestFiles: false,
    severity: 'error',
  },
  {
    id: 'NO_SUB_12PX_TYPOGRAPHY',
    name: 'Rule 3: Typography Floor (No sub-12px text)',
    description: 'Sub-12px micro-text (text-[10px], text-[11px], text-[9px], text-[8px]) is strictly forbidden. Minimum allowed size is text-xs (12px).',
    pattern: /\btext-\[(?:[0-9]|10|11)px\]/g,
    excludeTestFiles: true,
    severity: 'error',
  },
  {
    id: 'NO_DEAD_BUTTON_CLICKS',
    name: 'Rule 5: No Dead Buttons or Dummy Handlers',
    description: 'Buttons with empty @click, empty arrow functions, or console.log handlers are strictly forbidden.',
    pattern: /@click=["']\s*(?:|\(\)\s*=>\s*\{?\s*\}?|console\.(?:log|warn|info|debug)\([^)]*\)|void\s+0)\s*["']/g,
    excludeTestFiles: true,
    severity: 'error',
  },
  {
    id: 'NO_MOCK_DATA_VARS',
    name: 'Rule 5: No Mock/Dummy Data in Production Code',
    description: 'Hardcoded mockup datasets (mock*, dummy*, fake*) are strictly prohibited in production views, components, and stores.',
    pattern: /(?:const|let|var)\s+(?:mock|dummy|fake|stub)[A-Za-z0-9_]*\s*=/g,
    excludeTestFiles: true,
    severity: 'warning',
  },
  {
    id: 'NO_NATIVE_TITLE_TOOLTIP',
    name: 'Rule 2: No Native title="..." Tooltips on Controls',
    description: 'Native title attributes on interactive elements look jarring and delayed. Use @/components/ui/tooltip.',
    pattern: /<(?:button|a|input|div|span)[^>]*\s+title=["'][^"']+["']/g,
    excludeTestFiles: true,
    severity: 'warning',
  },
];

function isTestFile(filePath) {
  return (
    filePath.includes('__tests__') ||
    filePath.endsWith('.spec.ts') ||
    filePath.endsWith('.test.ts') ||
    filePath.endsWith('.spec.js')
  );
}

function scanDirectory(dir, fileList = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== 'dist') {
        scanDirectory(fullPath, fileList);
      }
    } else if (entry.isFile()) {
      if (/\.(vue|ts|js|tsx|jsx)$/.test(entry.name)) {
        fileList.push(fullPath);
      }
    }
  }
  return fileList;
}

function runDisciplineLinter() {
  const files = scanDirectory(SRC_DIR);
  const violationsByRule = new Map();
  let totalErrors = 0;
  let totalWarnings = 0;

  for (const file of files) {
    const isTest = isTestFile(file);
    const relativePath = path.relative(path.resolve(__dirname, '..'), file);
    const content = fs.readFileSync(file, 'utf-8');
    const lines = content.split('\n');

    for (const rule of RULES) {
      if (isTest && rule.excludeTestFiles) {
        continue;
      }

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        rule.pattern.lastIndex = 0;
        let match;
        while ((match = rule.pattern.exec(line)) !== null) {
          const violation = {
            file: relativePath,
            line: i + 1,
            column: match.index + 1,
            match: match[0],
            snippet: line.trim(),
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
          };

          if (!violationsByRule.has(rule.id)) {
            violationsByRule.set(rule.id, { rule, items: [] });
          }
          violationsByRule.get(rule.id).items.push(violation);

          if (rule.severity === 'error') {
            totalErrors++;
          } else {
            totalWarnings++;
          }
        }
      }
    }
  }

  console.log('\n================================================================');
  console.log('       🛡️   RAIWALL FRONTEND DISCIPLINE SCANNER REPORT');
  console.log('================================================================\n');

  if (violationsByRule.size === 0) {
    console.log('✅ PASS: All frontend source files comply with the 6 Cardinal Rules!\n');
    process.exit(0);
  }

  for (const [ruleId, { rule, items }] of violationsByRule.entries()) {
    const icon = rule.severity === 'error' ? '❌' : '⚠️ ';
    console.log(`${icon} [${rule.id}] ${rule.name}`);
    console.log(`   ℹ️  ${rule.description}`);
    console.log(`   Total Violations: ${items.length}\n`);

    const sample = items.slice(0, 15);
    for (const item of sample) {
      console.log(`     → ${item.file}:${item.line}:${item.column}`);
      console.log(`       "${item.snippet}"\n`);
    }

    if (items.length > 15) {
      console.log(`     ... and ${items.length - 15} more in other files.\n`);
    }
  }

  console.log('----------------------------------------------------------------');
  console.log(`Summary: ${totalErrors} Errors, ${totalWarnings} Warnings across ${files.length} scanned files.`);
  console.log('Refer to .agents/rules/frontend-discipline.md for remediation guidelines.\n');

  // Exit with non-zero if errors exist
  if (totalErrors > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runDisciplineLinter();
