1. Always declare variables at the top of each code block (immediately after the opening `{`).
2. Never use (void) for unused args; mark them with __clib_unused instead.
3. Prefer ASSERT over runtime error checks when validating internal (non-user) data.
4. Avoid memset when the same result can be achieved with struct initializers.
5. Only add #include directives when they are truly needed; rely on existing transitive includes whenever possible.
