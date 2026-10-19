# Demo app

A small reports API used in the demo video. `core/storage.py::load_report`
rejects names that contain `..` and nothing else, so it still opens absolute
paths and follows symbolic links. The bug is deliberate: it is the helper a new
endpoint is likely to reuse.

To run the demo yourself, copy the app out of this repository so it is its own
git repository, then start Claude Code in it:

```
cp -r examples/webapp /tmp/webapp && cd /tmp/webapp
git init -q && git add -A && git commit -qm "reports API"
claude
```

```
/secure-code-generation add GET /reports/<name> to api/routes.py that returns the report's lines as JSON, using load_report
```

The video ran this on Claude Code 2.1.301 with Sonnet 5.5 as the session model,
the attacker and verifier set to `Sonnet 5.5` in `/config` (so each runs as its
own subagent), and 3 to 5 probes per target. Results vary between runs: the
first version may already be safe, or a turn may find more than one weakness.

To audit the original code without writing anything new:

```
/check-code-security core/
```
