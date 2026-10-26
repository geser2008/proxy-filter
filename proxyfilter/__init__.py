__version__ = "0.1.0"

# Keep proxyfilter.speed as the compatibility surface while routing the public
# pipeline checks through the staged implementations and final speed policy.
from . import speed as _speed
from . import speed_reliability as _speed_reliability
from . import speed_staged as _speed_staged
from . import speed_result_policy as _speed_result_policy

_speed.check_download_many = _speed_result_policy.check_download_many
_speed.check_upload_many = _speed_result_policy.check_upload_many
