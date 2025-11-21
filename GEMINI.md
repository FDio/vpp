# VPP Codebase Context
> **CRITICAL:** These rules apply strictly when working on VPP (Vector Packet Processing) code.

## 1. Style & Syntax (Strict C89)
* **Variable Declarations:** MUST be at the very top of the scope (immediately after `{`). Do not mix declarations with code.
* **Comment Style:** Use C-style comments `/* ... */` ONLY.
    * **FORBIDDEN:** C++ style comments `//`.
* **Trailing Commas:** Always add a trailing comma inside brace lists `{ ... }` (arrays, enums, struct initializers), even for the last element.
    * Example: `foo_t f = { .a = 1, .b = 2, };`
* **No Cosmetic Changes:** Do NOT change whitespace, empty lines, or indentation unless strictly required for the fix. Preserve the existing "visual diff" as much as possible.
* **Includes:** Minimal headers only. Rely on transitive includes where possible.

## 2. Macros & Attributes
* **Unused Arguments:** Use the `__clib_unused` macro.
    * **FORBIDDEN:** Casting to void `(void)args;`.

## 3. Memory & Initialization
* **Struct Initialization:** Use aggregate initialization (`foo_t f = {0};`) instead of `memset`.
* **Nested Structs:**
    * If initializing **> 1 field** in a sub-struct, use nested braces.
    * If initializing **only 1 field**, flat notation is allowed.
* **Implicit Zeros:** In struct literals, do not explicitly assign `0` or `NULL` if the default initialization handles it.
* **Dead Initialization:** Do not initialize variables (e.g., `u32 x = 0;`) if they are unconditionally reassigned before use.

## 4. Error Handling
* **Internal State:** Use `ASSERT` for validating internal logic and invariants (non-user data).
* **Runtime Checks:** Use distinct error return paths only for external/input validation.

## 5. Workflow & Integrity
* **Source of Truth:** The current content of the file on disk is the ABSOLUTE source of truth.
    * **Rule:** Before generating code, you must assume the user has manually modified the file since your last turn.
    * **Constraint:** Never revert code to a previous state based on your conversation history. Always apply your fixes on top of the *current* text provided in the context.
* **Incremental Changes:** When asked to fix or update code, only output the specific sections that need changing (or use search/replace blocks) rather than rewriting the whole file, to minimize the risk of reverting unseen user changes.

## 6. Build & Development Environment
* **Configuration:** Use `./configure -n -t debug` (default) or use `release` if a release build is specifically requested.
* **Compilation:** Invoke `ninja` in the git root directory.
* **Formatting:** Use `git-clang-format` for formatting changes. Do not reformat entire files arbitrarily.
* **Execution:**
    * **Start VPP:** `ninja run`
    * **Debug VPP:** `ninja debug` (starts GDB with VPP loaded)

---

## VPP Coding Examples

### BAD (Violates VPP Rules)
```c
// C++ comment (Rule 1)
void vpp_feature_init(vlib_main_t *vm, int enable, int unused_arg) {
    (void)unused_arg; // Rule 2 violation

    // Rule 3: Flat notation used for >1 field in 'inner'
    complex_t c = {
        .val = 1,
        .inner.x = 10,
        .inner.y = 20, // Should be nested
        .ptr = NULL // Rule 3 (explicit zero) & Rule 1 (missing trailing comma)
    };
}
