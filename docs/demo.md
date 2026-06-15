# The 30-second demo

![The gate: rm -rf held before it runs](img/holdcard.svg)

> An AI agent proposes `rm -rf` → **Aegis holds it before it runs** → you press
> `d` → it's blocked and on the tamper-evident timeline.

## Run it

```sh
bash scripts/demo.sh
```

It is fully self-contained (its own socket, log, and `$PATH` shim in a temp dir)
and never touches your real config. When the hold card appears, press:

- `a` — allow once
- `d` — deny
- `r` — always allow this exact command in this repo

To run it non-interactively (for CI or a quick look):

```sh
DEMO_KEY=d bash scripts/demo.sh   # or DEMO_KEY=a
```

## What you'll see

```
▸ the agent now runs:  rm -rf .../project/src
  Aegis intercepts it BEFORE it executes and holds it.

────────────────────────────────────────────────────────────
⚠ Aegis hold — This command is catastrophic and cannot be undone.
  Recursively deletes files and directories.

    rm -rf src

  [a] allow once   [d] deny   [r] always allow here
────────────────────────────────────────────────────────────

✓ the file still exists — the deletion was held/denied:
important.txt

▸ everything is on the tamper-evident timeline:
time      agent         outcome  command
23:46:56  shim          held     [catastrophic] rm -rf src
23:46:56  shim          denied   [catastrophic] rm -rf src
```

The deletion never reached the real `rm`: interception happens *before*
execution.

## Record the GIF

Using [VHS](https://github.com/charmbracelet/vhs):

```sh
vhs scripts/demo.tape      # writes docs/aegis-demo.gif
```

Or record any terminal session with
[asciinema](https://asciinema.org/) + [agg](https://github.com/asciinema/agg):

```sh
asciinema rec demo.cast -c "bash scripts/demo.sh"
agg demo.cast docs/aegis-demo.gif
```
