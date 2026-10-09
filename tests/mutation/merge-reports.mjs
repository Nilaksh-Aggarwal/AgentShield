// Merges Stryker JSON reports of the same mutated code tested by different test projects, and prints the combined counts
// and every mutant no report detected.
//
//   node merge-reports.mjs StrykerOutput/<api-tests run>/reports/mutation-report.json StrykerOutput/<integration run>/reports/mutation-report.json
//
// Why: Stryker.NET 5 with two test projects in one run reported mutants as surviving that the ApiTests run alone kills
// (docs/decisions/0018-assurance-tooling.md). The API boundary scope is therefore run once per test project. A mutant
// is detected if any run killed it or timed out on it; it survived if a run covered it and none detected it.
import { readFileSync } from 'node:fs'
import { basename } from 'node:path'

const paths = process.argv.slice(2)
if (paths.length < 2) {
  console.error('Usage: node merge-reports.mjs <report.json> <report.json> [...]')
  process.exit(2)
}

const rank = { Killed: 5, Timeout: 4, Survived: 3, NoCoverage: 2, CompileError: 1, Ignored: 0 }
const merged = new Map()
for (const path of paths) {
  const report = JSON.parse(readFileSync(path, 'utf8'))
  for (const [file, { mutants }] of Object.entries(report.files)) {
    for (const mutant of mutants) {
      const { line, column } = mutant.location.start
      const key = `${basename(file)}:${line}:${column}:${mutant.mutatorName}:${mutant.replacement ?? ''}`
      const previous = merged.get(key)
      if (!previous || rank[mutant.status] > rank[previous.status]) {
        merged.set(key, { file: basename(file), line, status: mutant.status, mutator: mutant.mutatorName, replacement: mutant.replacement ?? '' })
      }
    }
  }
}

const counts = {}
for (const { status } of merged.values()) {
  counts[status] = (counts[status] ?? 0) + 1
}

const n = (status) => counts[status] ?? 0
const detected = n('Killed') + n('Timeout')
const valid = detected + n('Survived') + n('NoCoverage')
console.log(`mutants ${merged.size}: valid ${valid}, compile errors ${n('CompileError')}, ignored ${n('Ignored')}`)
console.log(`killed ${n('Killed')}, timeout ${n('Timeout')}, survived ${n('Survived')}, no coverage ${n('NoCoverage')}`)
console.log(`mutation score ${(100 * detected / valid).toFixed(2)}%, covered-code score ${(100 * detected / (detected + n('Survived'))).toFixed(2)}%`)
for (const mutant of [...merged.values()].filter(({ status }) => status === 'Survived' || status === 'NoCoverage')
  .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line)) {
  console.log(`  ${mutant.status.padEnd(10)} ${mutant.file}:${mutant.line} ${mutant.mutator} -> ${mutant.replacement.replace(/\s+/g, ' ').slice(0, 80)}`)
}
