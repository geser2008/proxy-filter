__version__ = "0.1.0"

# Keep the existing proxyfilter.speed module as the compatibility surface while
# routing the pipeline's public speed checks through the staged implementation.
# Existing low-level helpers/tests remain import-compatible.
from . import speed as _speed
from . import speed_staged as _speed_staged

_speed.check_download_many = _speed_staged.check_download_many
_speed.check_upload_many = _speed_staged.check_upload_many
