import { join } from "jsr:@std/path@^1.0.0/mod.ts";
import type { Ghost } from "jsr:@fake/types@1.0.0";
import "https://user:secret@cdn.example.test/mod.ts?token=hidden";
export { isNumber } from "./helper.ts";
const lazy = import("npm:chalk@5.3.0");
const runtime = import(name);
const example = 'import "jsr:@fake/package@1.0.0"';
// import "jsr:@fake/comment@1.0.0";
console.log(join, lazy, runtime, example);
