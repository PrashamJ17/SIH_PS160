"""IPsec Sentinel — passive IPsec/IKE protocol analysis and security assessment.

The package is built around one invariant: facts are parsed, estimates are inferred.
Anything read from the cleartext IKE handshake is deterministic and carries no
confidence value; anything derived from encrypted traffic is inferred and carries a
calibrated one. The two lanes never mix.
"""
