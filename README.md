# UV experiment

Proof of concept:

- [ ] Dependency management
  - [x] Basic dependencies
  - [x] Charm-lib
  - [x] Workflow dependencies
  - [ ] Development dependencies with groups
  - [x] Renovate rule for charm-libs
- [x] Task runner with tox
- [x] Build (not yet working with strict deps)
- [x] CI

## uv integration with standard tooling and common operations

Using poetry, we would either create the venv before using poetry (using the venv module for instance), or let poetry handle its creation upon the first run.
How to create a virtual env for the editor (used for autocomplete and diagnostics):

```shell
# using venv module
python -m venv venv

# using poetry, the venv could be created in-project, or in a common venv directory
poetry install

# using uv
uv venv -p 3.10 venv
```

To use tox, make sure to install (or inject) `tox-uv`.

```shell
uv tool install tox --with tox-uv
```

## Multi-arch lock file

Should be good with the default uv.lock file https://docs.astral.sh/uv/concepts/projects/#project-lockfile.

## Support for (dev) dependency groups

[PEP 735](https://peps.python.org/pep-0735/) was recently accepted. Progress for supporting PEP 735 in uv is tracked [here](https://github.com/astral-sh/uv/issues/8090).
The final syntax _should_ look like this:

```shell
# current with poetry

[tool.poetry.group.fmt]
optional = true

[tool.poetry.group.fmt.dependencies]
black = "^22.3.0"
ruff = ">=0.1.0"

[tool.poetry.group.lint]
optional = true

[tool.poetry.group.lint.dependencies]
black = "^22.3.0"
ruff = ">=0.1.0"
codespell = ">=2.2.2"
pyright = "^1.1.301"
lightkube = "0.15.0"
```

```shell
# uv with PEP 735 support
[dependency-groups]
fmt = [
  "black ~= 22.3",
  "ruff >= 0.1.0",
]
lint = [
  "black ~= 22.3",
  "ruff >= 0.1.0",
  "codespell >= 2.2.2",
  "pyright >= 1.1.301, <2",
  "lightkube == 0.15.0",
]
```

Note that the constraint syntax is not the same. In particular: ~ and ~= do not mean the same for [poetry](https://python-poetry.org/docs/dependency-specification/#tilde-requirements) and [uv](https://docs.astral.sh/uv/concepts/dependencies/#pep-508).

## Renovate

Make sure you have a local `renovate` (minimum 38.114.0 to get the new "matchJsonata" rule).

```shell
RENOVATE_CONFIG_FILE=./renovate.json5 LOG_LEVEL=debug renovate --plaform=local --onboarding=false
```

Then, you can assert that the charm-libs dependencies are properly matched and disabled according to our rules.
