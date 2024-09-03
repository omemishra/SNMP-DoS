import argparse
from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, bulkCmd, ObjectType, ObjectIdentity

def check_snmp_reflection(target_ip, community_string='public'):
    error_indication, error_status, error_index, var_binds = next(
        bulkCmd(
            SnmpEngine(),
            CommunityData(community_string, mpModel=1),  # SNMPv2c
            UdpTransportTarget((target_ip, 161)),
            ContextData(),
            0, 10,  # non-repeaters, max-repetitions
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1')),  # sysDescr OID
            lookupMib=False
        )
    )

    if error_indication:
        print(f"Error: {error_indication}")
        return False
    elif error_status:
        print(f"Error: {error_status.prettyPrint()} at {error_index}")
        return False
    else:
        response_size = sum(len(str(var_bind)) for var_bind in var_binds)
        request_size = len(community_string) + 8  # rough estimate

        print(f"Request size: {request_size} bytes")
        print(f"Response size: {response_size} bytes")

        amplification_factor = response_size / request_size if request_size else 0
        print(f"Amplification Factor: {amplification_factor:.2f}")

        if amplification_factor > 1:
            print(f"\033[91m[!] {target_ip} is vulnerable to SNMP reflection/amplification\033[0m")
            return True
        else:
            print(f"[-] {target_ip} is not vulnerable")
            return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check SNMP reflection and amplification vulnerability.")
    parser.add_argument("target_ip", help="Target IP address to check")
    parser.add_argument("--community", default="public", help="SNMP community string (default: public)")

    args = parser.parse_args()
    check_snmp_reflection(args.target_ip, args.community)
