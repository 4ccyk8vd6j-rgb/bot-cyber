import inspect

import pytest

from cyberbot import modules


@pytest.mark.parametrize("name", sorted(modules.REGISTRY))
def test_module_loads_and_exposes_run(name):
    mod = modules.load(name)
    assert hasattr(mod, "NAME"), f"{name} doit exposer NAME"
    assert callable(getattr(mod, "run", None)), f"{name} doit exposer run()"
    params = list(inspect.signature(mod.run).parameters)
    assert params[:2] == ["target", "ctx"], f"{name}.run doit accepter (target, ctx)"


def test_load_unknown_module_raises():
    with pytest.raises(KeyError):
        modules.load("module-inexistant")
