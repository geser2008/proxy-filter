__version__ = "0.1.0"

# Keep proxyfilter.speed as the compatibility surface while routing the public
# pipeline checks through the staged implementations and final policy wrappers.
from . import speed as _speed
from . import speed_reliability as _speed_reliability
from . import speed_semantics as _speed_semantics

_speed.check_download_many = _speed_reliability.check_download_many
_speed.check_upload_many = _speed_semantics.check_upload_many

# Keep the existing import surface used by cli.py while routing the concrete
# backend class through the dual standard/extended mode adapter.
from . import singbox_backend as _singbox_backend
from .singbox_modes import SingBoxBackend as _ModeSingBoxBackend

_singbox_backend.SingBoxBackend = _ModeSingBoxBackend
