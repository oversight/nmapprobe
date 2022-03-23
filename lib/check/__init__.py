from .checkCertificates import CheckCertificates
from .checkPorts import CheckPorts

CHECKS = {
    'CheckCertificates': CheckCertificates,
    'CheckPorts': CheckPorts
}
