/* Extracts one version's section from CHANGELOG.md, for use as GitHub Release
 * notes.
 *
 * Usage: node scripts/changelog-section.js 1.1.0
 *
 * Prints everything between the `## [1.1.0]` heading and the next `##`
 * heading, with the link-reference definitions at the bottom of the file
 * appended so that `[1.1.0]`-style links still resolve. Exits non-zero if the
 * version has no section, which is what makes a release fail fast rather than
 * shipping empty notes.
 */
import { readFileSync } from "node:fs";

const version = process.argv[2];

if (!version) {
  console.error("usage: node scripts/changelog-section.js <version>");
  process.exit(2);
}

const changelog = readFileSync("CHANGELOG.md", "utf8");
const lines = changelog.split("\n");

// Matches "## [1.1.0] - 2026-08-11" and "## 1.1.0", but not "## [1.1.0-rc.1]".
const heading = new RegExp(
  `^##\\s+\\[?${version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\]?(\\s|$)`,
);

const start = lines.findIndex((line) => heading.test(line));

if (start === -1) {
  console.error(`No section for version ${version} found in CHANGELOG.md.`);
  process.exit(1);
}

let end = lines.length;
for (let i = start + 1; i < lines.length; i++) {
  if (/^##\s/.test(lines[i])) {
    end = i;
    break;
  }
}

const isReference = (line) => /^\[[^\]]+\]:\s/.test(line);

// The reference definitions live at the bottom of the file, which means they
// fall inside the *last* version's section. Strip them from the body first, or
// the oldest release gets them twice.
const body = lines.slice(start + 1, end).filter((line) => !isReference(line));

if (body.join("").trim() === "") {
  console.error(`The section for version ${version} in CHANGELOG.md is empty.`);
  process.exit(1);
}

// Re-append them so that "[1.1.0]"-style links in the body still resolve.
const references = lines.filter(isReference);

console.log([...body, ...references].join("\n").trim());
