__version__ = "0.1.0"

# Keep proxyfilter.speed as the compatibility surface while routing the public
# pipeline checks through the staged implementations.
from . import speed as _speed
from . import speed_reliability as _speed_reliability
from . import speed_staged as _speed_staged

_speed.check_download_many = _speed_reliability.check_download_many
_speed.check_upload_many = _speed_staged.check_upload_many

# A numeric speed measurement is authoritative for threshold decisions even if
# the transfer later ends with a timeout/error. Only a missing measurement is
# rejected as a measurement error.
from . import measurement_policy as _measurement_policy

_speed.check_download_many = _measurement_policy.check_download_many
_speed.check_upload_many = _measurement_policy.check_upload_many
